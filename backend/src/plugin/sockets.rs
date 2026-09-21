//! The one generic capability a deployer-supplied plugin gets: a raw TCP
//! socket, optionally wrapped in TLS.
//!
//! WeaveAuth ships no protocol knowledge. Postgres wire, AMQP, Kafka, SMTP,
//! a SOAP envelope -- all of it is the plugin's problem above this layer,
//! which only moves bytes. That is what keeps the core generic: adding a new
//! kind of downstream system is a deployer swapping their `.wasm` file, not
//! a change here.
//!
//! Connections are pooled *host-side*, keyed by endpoint, because a plugin
//! instance is created per call and cannot hold one. `sock_open` reports
//! whether the connection it handed back is `fresh`, which is what lets a
//! plugin skip a protocol handshake it already performed on a pooled
//! connection.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use extism::{Function, UserData, host_fn};
use serde::Deserialize;
use serde_json::{Value, json};

/// Anything the host can move bytes over. Boxed so a plain TCP stream and a
/// TLS stream can share one pool.
trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// Ceiling on a single `sock_read`, regardless of the `max` the plugin asks
/// for -- the request is attacker-influenced in the sense that a buggy or
/// hostile plugin could ask for `usize::MAX` and make the host allocate it.
const MAX_READ_BYTES: usize = 1024 * 1024;

/// A pooled endpoint: the `tls` flag is part of the key because a plaintext
/// connection and a TLS one to the same host:port are not interchangeable.
type Endpoint = (String, u16, bool);

/// A live connection plus a dup of its underlying socket. The dup exists
/// only to re-arm read/write deadlines per operation: `dyn Stream` can't
/// expose them, and the remaining call budget shrinks between operations.
struct Conn {
    stream: Box<dyn Stream>,
    control: TcpStream,
}

impl Conn {
    fn set_deadline(&self, budget: Duration) -> Result<(), SocketError> {
        self.control
            .set_read_timeout(Some(budget))
            .and_then(|()| self.control.set_write_timeout(Some(budget)))
            .map_err(|error| SocketError::new(ErrorCode::Io, format!("cannot arm the socket deadline: {error}")))
    }
}

struct Pooled {
    conn: Conn,
    returned_at: Instant,
}

/// Why a socket operation failed, as a stable string the plugin can match on
/// -- the human-readable message is for a log, not for control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    /// The endpoint isn't in the deployer's allowlist.
    NotAllowed,
    /// The call's wall-clock budget is spent, or a single operation hit its
    /// own deadline.
    Timeout,
    /// No such handle in this call.
    UnknownHandle,
    /// The call already opened as many connections as it's allowed.
    TooManyConnections,
    /// The request wasn't valid JSON for this operation.
    BadRequest,
    /// The socket capability isn't available here at all.
    Unavailable,
    /// Anything the peer or the network did.
    Io,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotAllowed => "not_allowed",
            ErrorCode::Timeout => "timeout",
            ErrorCode::UnknownHandle => "unknown_handle",
            ErrorCode::TooManyConnections => "too_many_connections",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Io => "io",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SocketError {
    code: ErrorCode,
    message: String,
}

impl SocketError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

/// Parses a deployer-configured `host:port` endpoint.
pub(crate) fn parse_endpoint(raw: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("plugin socket endpoint {raw:?} must be in host:port form"))?;
    if host.is_empty() {
        anyhow::bail!("plugin socket endpoint {raw:?} has an empty host");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("plugin socket endpoint {raw:?} has an invalid port"))?;
    Ok((host.to_string(), port))
}

/// Bounds on what one plugin call may do with the socket capability.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SocketLimits {
    pub(crate) max_idle_per_endpoint: usize,
    /// How many connections a single call may open. Bounds the dials a
    /// runaway plugin can aim at a downstream system within its deadline.
    pub(crate) max_open_per_call: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) io_timeout: Duration,
}

/// Owns the allowlist and the idle-connection pool. Shared by every plugin
/// call; the per-call handle table lives in [`CallScope`].
pub(crate) struct SocketHost {
    allowed: Vec<(String, u16)>,
    idle: Mutex<HashMap<Endpoint, Vec<Pooled>>>,
    limits: SocketLimits,
}

impl SocketHost {
    pub(crate) fn new(allowed: Vec<(String, u16)>, limits: SocketLimits) -> Self {
        Self { allowed, idle: Mutex::new(HashMap::new()), limits }
    }

    /// Drops every pooled connection that has been idle past its timeout.
    /// Called on the same interval as the TTL'd stores: `take_idle` only
    /// expires connections for the endpoint being asked for, so an endpoint
    /// that stops being used would otherwise hold its sockets open until the
    /// process exits.
    pub(crate) fn sweep_idle(&self) {
        let Ok(mut idle) = self.idle.lock() else {
            return;
        };
        for slots in idle.values_mut() {
            slots.retain(|pooled| pooled.returned_at.elapsed() < self.limits.idle_timeout);
        }
        idle.retain(|_, slots| !slots.is_empty());
    }

    /// How many connections are currently pooled, across every endpoint.
    #[cfg(test)]
    pub(crate) fn pooled_count(&self) -> usize {
        self.idle.lock().expect("pool is not poisoned").values().map(Vec::len).sum()
    }

    fn checkout(&self, host: &str, port: u16, tls: bool, budget: Duration) -> Result<(Conn, bool), SocketError> {
        if !self.allowed.iter().any(|(allowed, allowed_port)| allowed == host && *allowed_port == port) {
            return Err(SocketError::new(
                ErrorCode::NotAllowed,
                format!("endpoint {host}:{port} is not in the plugin socket allowlist"),
            ));
        }
        match self.take_idle(&(host.to_string(), port, tls)) {
            Some(conn) => Ok((conn, false)),
            None => Ok((self.dial(host, port, tls, budget)?, true)),
        }
    }

    /// A connection idle past `idle_timeout` is dropped rather than handed
    /// back: the peer has most likely closed it, and a plugin told
    /// `fresh: false` would replay its session onto a dead socket.
    fn take_idle(&self, endpoint: &Endpoint) -> Option<Conn> {
        let mut idle = self.idle.lock().ok()?;
        let slots = idle.get_mut(endpoint)?;
        while let Some(pooled) = slots.pop() {
            if pooled.returned_at.elapsed() < self.limits.idle_timeout {
                return Some(pooled.conn);
            }
        }
        None
    }

    fn dial(&self, host: &str, port: u16, tls: bool, budget: Duration) -> Result<Conn, SocketError> {
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|error| SocketError::new(ErrorCode::Io, format!("cannot resolve {host}:{port}: {error}")))?
            .next()
            .ok_or_else(|| SocketError::new(ErrorCode::Io, format!("{host}:{port} resolved to no addresses")))?;

        let stream = TcpStream::connect_timeout(&address, budget)
            .map_err(|error| SocketError::new(ErrorCode::Io, format!("cannot connect to {host}:{port}: {error}")))?;
        let control = stream
            .try_clone()
            .map_err(|error| SocketError::new(ErrorCode::Io, format!("cannot dup the socket: {error}")))?;

        let conn = if tls {
            // TLS host-side so a plugin doesn't have to carry a crypto stack
            // into wasm -- still protocol-agnostic, it's bytes either way.
            let connector = native_tls::TlsConnector::new()
                .map_err(|error| SocketError::new(ErrorCode::Io, format!("cannot build a TLS client: {error}")))?;
            let stream = connector.connect(host, stream).map_err(|error| {
                SocketError::new(ErrorCode::Io, format!("TLS handshake with {host}:{port} failed: {error}"))
            })?;
            Conn { stream: Box::new(stream), control }
        } else {
            Conn { stream: Box::new(stream), control }
        };
        conn.set_deadline(budget)?;
        Ok(conn)
    }

    fn checkin(&self, endpoint: Endpoint, conn: Conn) {
        let Ok(mut idle) = self.idle.lock() else {
            return;
        };
        let slots = idle.entry(endpoint).or_default();
        if slots.len() < self.limits.max_idle_per_endpoint {
            slots.push(Pooled { conn, returned_at: Instant::now() });
        }
    }
}

struct Open {
    conn: Conn,
    endpoint: Endpoint,
    /// Set the moment an operation on this connection fails. A failed read
    /// or write can leave unread bytes or a half-written frame behind, so
    /// the connection is no longer safe to hand to the next call whatever
    /// the plugin claims when it releases it.
    dirty: Cell<bool>,
}

/// One plugin call's handle table and wall-clock budget. Handles are
/// allocated per scope, so a call can only name connections it opened
/// itself, and anything still open when the scope ends is closed rather than
/// pooled -- the plugin never declared it clean.
pub(crate) struct CallScope {
    host: Arc<SocketHost>,
    open: RefCell<HashMap<u64, Open>>,
    next_handle: Cell<u64>,
    opened: Cell<usize>,
    deadline: Instant,
}

thread_local! {
    /// Host functions run synchronously on the thread executing the wasm
    /// call, so the scope reaches them through here instead of having to be
    /// threaded through wasm as an argument the plugin could forge.
    static CURRENT_SCOPE: RefCell<Option<Rc<CallScope>>> = const { RefCell::new(None) };
}

/// Clears the thread's scope, closing (not pooling) whatever the plugin left
/// open, when the call it belongs to returns.
pub(crate) struct ScopeGuard;

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        CURRENT_SCOPE.with(|current| current.borrow_mut().take());
    }
}

impl CallScope {
    /// Installs a scope for the current plugin call, budgeted to finish
    /// within `timeout`. The returned guard must outlive the call.
    pub(crate) fn enter(host: &Arc<SocketHost>, timeout: Duration) -> ScopeGuard {
        let scope = Rc::new(Self {
            host: host.clone(),
            open: RefCell::new(HashMap::new()),
            next_handle: Cell::new(1),
            opened: Cell::new(0),
            deadline: Instant::now() + timeout,
        });
        CURRENT_SCOPE.with(|current| *current.borrow_mut() = Some(scope));
        ScopeGuard
    }

    /// What a single operation may spend: whatever is left of the call's
    /// budget, capped at the per-operation timeout.
    ///
    /// The plugin timeout is wasmtime epoch interruption, which interrupts
    /// *wasm* execution and cannot interrupt a host call blocked on a
    /// socket. Without a shared budget a plugin could chain an unbounded
    /// number of `io_timeout`-long operations and outlive that timeout
    /// however many times over it liked.
    fn budget(&self) -> Result<Duration, SocketError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SocketError::new(ErrorCode::Timeout, "the plugin call's time budget is spent"));
        }
        Ok(remaining.min(self.host.limits.io_timeout))
    }

    fn open(&self, host: &str, port: u16, tls: bool) -> Result<(u64, bool), SocketError> {
        let budget = self.budget()?;
        if self.opened.get() >= self.host.limits.max_open_per_call {
            return Err(SocketError::new(
                ErrorCode::TooManyConnections,
                format!("a call may open at most {} connections", self.host.limits.max_open_per_call),
            ));
        }

        let (conn, fresh) = self.host.checkout(host, port, tls, budget)?;
        self.opened.set(self.opened.get() + 1);
        let handle = self.next_handle.get();
        self.next_handle.set(handle + 1);
        self.open.borrow_mut().insert(
            handle,
            Open { conn, endpoint: (host.to_string(), port, tls), dirty: Cell::new(false) },
        );
        Ok((handle, fresh))
    }

    fn write(&self, handle: u64, data: &[u8]) -> Result<usize, SocketError> {
        self.with_conn(handle, |conn| {
            conn.stream
                .write_all(data)
                .and_then(|()| conn.stream.flush())
                .map_err(|error| SocketError::new(ErrorCode::Io, error.to_string()))?;
            Ok(data.len())
        })
    }

    fn read(&self, handle: u64, max: usize) -> Result<(Vec<u8>, bool), SocketError> {
        self.with_conn(handle, |conn| {
            let mut buffer = vec![0u8; read_buffer_size(max)];
            let read = conn
                .stream
                .read(&mut buffer)
                .map_err(|error| SocketError::new(ErrorCode::Io, error.to_string()))?;
            buffer.truncate(read);
            Ok((buffer, read == 0))
        })
    }

    fn release(&self, handle: u64, reuse: bool) -> Result<(), SocketError> {
        let open = self
            .open
            .borrow_mut()
            .remove(&handle)
            .ok_or_else(|| SocketError::new(ErrorCode::UnknownHandle, unknown_handle(handle)))?;
        if reuse && !open.dirty.get() {
            self.host.checkin(open.endpoint, open.conn);
        }
        Ok(())
    }

    /// Re-arms the connection's deadline from the remaining call budget, runs
    /// one operation, and marks the connection dirty if it failed.
    fn with_conn<T>(&self, handle: u64, f: impl FnOnce(&mut Conn) -> Result<T, SocketError>) -> Result<T, SocketError> {
        let budget = self.budget()?;
        let mut open = self.open.borrow_mut();
        let entry = open
            .get_mut(&handle)
            .ok_or_else(|| SocketError::new(ErrorCode::UnknownHandle, unknown_handle(handle)))?;

        entry.conn.set_deadline(budget).inspect_err(|_| entry.dirty.set(true))?;
        f(&mut entry.conn).inspect_err(|_| entry.dirty.set(true))
    }
}

/// Bounds the buffer a single `sock_read` allocates, whatever the plugin
/// asked for.
fn read_buffer_size(max: usize) -> usize {
    max.min(MAX_READ_BYTES)
}

fn unknown_handle(handle: u64) -> String {
    format!("unknown socket handle {handle}")
}

#[derive(Deserialize)]
struct OpenRequest {
    host: String,
    port: u16,
    #[serde(default)]
    tls: bool,
}

#[derive(Deserialize)]
struct WriteRequest {
    handle: u64,
    /// base64, so the whole ABI stays JSON in every guest language.
    data: String,
}

#[derive(Deserialize)]
struct ReadRequest {
    handle: u64,
    max: usize,
}

#[derive(Deserialize)]
struct ReleaseRequest {
    handle: u64,
    #[serde(default)]
    reuse: bool,
}

/// Runs one socket operation against the current call's scope and renders
/// the result as JSON. Failures come back as `{"status":"error"}` data
/// rather than a wasm trap: a refused endpoint or a dead peer is the
/// plugin's to handle, not a reason to kill the registration outright.
fn dispatch(request: &str, op: impl FnOnce(&CallScope, &str) -> Result<Value, SocketError>) -> String {
    let scope = CURRENT_SCOPE.with(|current| current.borrow().clone());
    let result = match scope {
        Some(scope) => op(&scope, request),
        None => Err(SocketError::new(
            ErrorCode::Unavailable,
            "the socket capability is not available in this call",
        )),
    };

    match result {
        Ok(value) => {
            let mut response = json!({"status": "ok"});
            if let (Some(response), Some(value)) = (response.as_object_mut(), value.as_object()) {
                response.extend(value.iter().map(|(key, value)| (key.clone(), value.clone())));
            }
            response.to_string()
        }
        Err(error) => {
            json!({"status": "error", "code": error.code.as_str(), "message": error.message}).to_string()
        }
    }
}

fn parse<'a, T: Deserialize<'a>>(request: &'a str, op: &str) -> Result<T, SocketError> {
    serde_json::from_str(request)
        .map_err(|error| SocketError::new(ErrorCode::BadRequest, format!("invalid {op} request: {error}")))
}

host_fn!(sock_open(_user_data: (); request: String) -> String {
    Ok(dispatch(&request, |scope, request| {
        let request: OpenRequest = parse(request, "sock_open")?;
        let (handle, fresh) = scope.open(&request.host, request.port, request.tls)?;
        Ok(json!({"handle": handle, "fresh": fresh}))
    }))
});

host_fn!(sock_write(_user_data: (); request: String) -> String {
    Ok(dispatch(&request, |scope, request| {
        let request: WriteRequest = parse(request, "sock_write")?;
        let data = base64::engine::general_purpose::STANDARD.decode(&request.data).map_err(|error| {
            SocketError::new(ErrorCode::BadRequest, format!("sock_write data is not valid base64: {error}"))
        })?;
        let written = scope.write(request.handle, &data)?;
        Ok(json!({"written": written}))
    }))
});

host_fn!(sock_read(_user_data: (); request: String) -> String {
    Ok(dispatch(&request, |scope, request| {
        let request: ReadRequest = parse(request, "sock_read")?;
        let (data, eof) = scope.read(request.handle, request.max)?;
        Ok(json!({"data": base64::engine::general_purpose::STANDARD.encode(data), "eof": eof}))
    }))
});

host_fn!(sock_release(_user_data: (); request: String) -> String {
    Ok(dispatch(&request, |scope, request| {
        let request: ReleaseRequest = parse(request, "sock_release")?;
        scope.release(request.handle, request.reuse)?;
        Ok(json!({}))
    }))
});

/// The imports a plugin sees when the deployer configures the socket
/// capability. Nothing is registered when it isn't, so a module importing
/// these fails to instantiate rather than silently getting no network.
pub(crate) fn host_functions() -> Vec<Function> {
    use extism::PTR;

    vec![
        Function::new("sock_open", [PTR], [PTR], UserData::new(()), sock_open),
        Function::new("sock_write", [PTR], [PTR], UserData::new(()), sock_write),
        Function::new("sock_read", [PTR], [PTR], UserData::new(()), sock_read),
        Function::new("sock_release", [PTR], [PTR], UserData::new(()), sock_release),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    const IO_TIMEOUT: Duration = Duration::from_secs(2);

    /// Accepts `count` connections, echoing one line per connection, and
    /// reports how many it accepted so a test can tell a pooled connection
    /// from a freshly dialled one.
    fn echo_server(count: usize) -> (String, u16, mpsc::Receiver<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            for (accepted, stream) in listener.incoming().take(count).enumerate() {
                let Ok(mut stream) = stream else { continue };
                tx.send(accepted + 1).ok();
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 64];
                    while let Ok(read) = stream.read(&mut buffer) {
                        if read == 0 || stream.write_all(&buffer[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        ("127.0.0.1".to_string(), port, rx)
    }

    const CALL_TIMEOUT: Duration = Duration::from_secs(30);

    fn limits(idle_timeout: Duration) -> SocketLimits {
        SocketLimits {
            max_idle_per_endpoint: 8,
            max_open_per_call: 8,
            idle_timeout,
            io_timeout: IO_TIMEOUT,
        }
    }

    /// Accepts connections and never sends anything, so a read against it
    /// can only end in the timeout.
    fn silent_server() -> (String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("has an address").port();

        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => held.push(stream),
                    Err(_) => return,
                }
            }
        });

        ("127.0.0.1".to_string(), port)
    }

    fn host(allowed: Vec<(String, u16)>, idle_timeout: Duration) -> Arc<SocketHost> {
        Arc::new(SocketHost::new(allowed, limits(idle_timeout)))
    }

    /// Drives a scope the way a plugin call does, so a test exercises the
    /// same per-call lifecycle the host functions see.
    fn in_scope<T>(host: &Arc<SocketHost>, f: impl FnOnce(&CallScope) -> T) -> T {
        with_budget(host, CALL_TIMEOUT, f)
    }

    fn with_budget<T>(host: &Arc<SocketHost>, timeout: Duration, f: impl FnOnce(&CallScope) -> T) -> T {
        let _guard = CallScope::enter(host, timeout);
        let scope = CURRENT_SCOPE.with(|current| current.borrow().clone()).expect("scope is installed");
        f(&scope)
    }

    #[test]
    fn parses_a_host_port_endpoint() {
        assert_eq!(parse_endpoint("db:5432").expect("parses"), ("db".to_string(), 5432));
        assert_eq!(parse_endpoint("127.0.0.1:80").expect("parses"), ("127.0.0.1".to_string(), 80));
    }

    #[test]
    fn rejects_a_malformed_endpoint() {
        assert!(parse_endpoint("db").is_err());
        assert!(parse_endpoint(":5432").is_err());
        assert!(parse_endpoint("db:not-a-port").is_err());
        assert!(parse_endpoint("db:99999").is_err());
    }

    #[test]
    fn refuses_an_endpoint_that_is_not_allowlisted() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port + 1)], Duration::from_secs(30));

        let result = in_scope(&host, |scope| scope.open(&address, port, false));

        assert!(result.is_err(), "a plugin reached an endpoint outside the allowlist");
    }

    // Positive control for `refuses_an_endpoint_that_is_not_allowlisted`:
    // without it, refusing every endpoint would leave that test green.
    #[test]
    fn opens_an_allowlisted_endpoint() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        let (_handle, fresh) = in_scope(&host, |scope| scope.open(&address, port, false)).expect("opens");

        assert!(fresh, "a first connection to an endpoint must be reported as fresh");
    }

    #[test]
    fn round_trips_bytes_over_a_connection() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        let echoed = in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.write(handle, b"ping").expect("writes");
            scope.read(handle, 64).expect("reads")
        });

        assert_eq!(echoed.0, b"ping");
        assert!(!echoed.1, "a read that returned data must not report eof");
    }

    // Literal expectations rather than `MAX_READ_BYTES`: asserting against
    // the constant under test passes whatever value it holds.
    #[test]
    fn caps_a_read_buffer_regardless_of_what_the_plugin_asks_for() {
        assert_eq!(read_buffer_size(usize::MAX), 1_048_576);
        assert_eq!(read_buffer_size(4_194_304), 1_048_576);
        assert_eq!(read_buffer_size(64), 64);
    }

    #[test]
    fn reuses_a_connection_released_for_reuse() {
        let (address, port, accepts) = echo_server(2);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            let (handle, fresh) = scope.open(&address, port, false).expect("opens");
            assert!(fresh);
            scope.release(handle, true).expect("releases");
        });
        let fresh_again = in_scope(&host, |scope| {
            let (handle, fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(handle, true).expect("releases");
            fresh
        });

        assert!(!fresh_again, "a pooled connection was re-dialled instead of reused");
        assert_eq!(accepts.recv().expect("first accept"), 1);
        assert!(accepts.try_recv().is_err(), "the server saw a second connection");
    }

    #[test]
    fn does_not_pool_a_connection_released_without_reuse() {
        let (address, port, accepts) = echo_server(2);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(handle, false).expect("releases");
        });
        let fresh_again = in_scope(&host, |scope| scope.open(&address, port, false).expect("opens").1);

        assert!(fresh_again, "a connection the plugin did not declare clean was pooled");
        assert_eq!(accepts.recv().expect("first accept"), 1);
        assert_eq!(accepts.recv().expect("second accept"), 2);
    }

    #[test]
    fn does_not_pool_a_connection_the_plugin_left_open() {
        let (address, port, accepts) = echo_server(2);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            scope.open(&address, port, false).expect("opens");
        });
        let fresh_again = in_scope(&host, |scope| scope.open(&address, port, false).expect("opens").1);

        assert!(fresh_again, "a connection abandoned mid-protocol was handed to the next call");
        assert_eq!(accepts.recv().expect("first accept"), 1);
        assert_eq!(accepts.recv().expect("second accept"), 2);
    }

    #[test]
    fn discards_a_pooled_connection_past_the_idle_timeout() {
        let (address, port, accepts) = echo_server(2);
        let host = host(vec![(address.clone(), port)], Duration::from_millis(1));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(handle, true).expect("releases");
        });
        std::thread::sleep(Duration::from_millis(20));
        let fresh_again = in_scope(&host, |scope| scope.open(&address, port, false).expect("opens").1);

        assert!(fresh_again, "a stale pooled connection was handed back as reusable");
        assert_eq!(accepts.recv().expect("first accept"), 1);
        assert_eq!(accepts.recv().expect("second accept"), 2);
    }

    #[test]
    fn a_handle_from_one_call_is_not_usable_in_the_next() {
        let (address, port, _accepts) = echo_server(2);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        let leaked = in_scope(&host, |scope| scope.open(&address, port, false).expect("opens").0);
        let result = in_scope(&host, |scope| scope.write(leaked, b"ping"));

        assert!(result.is_err(), "a call reached a handle it did not open");
    }

    #[test]
    fn rejects_an_unknown_handle() {
        let host = host(vec![], Duration::from_secs(30));

        let (write, read, release) = in_scope(&host, |scope| {
            (scope.write(7, b"ping"), scope.read(7, 8), scope.release(7, true))
        });

        for error in [write.expect_err("write fails"), read.expect_err("read fails"), release.expect_err("release fails")] {
            assert_eq!(error.code, ErrorCode::UnknownHandle);
            assert!(error.message.contains("7"), "the error must name the handle it refused");
        }
    }

    // Without this, `ScopeGuard::drop` could do nothing and every other test
    // would still pass -- `CallScope::enter` overwrites the thread's scope
    // anyway. What leaks is the window between calls, where the finished
    // call's connections are still reachable.
    #[test]
    fn the_scope_is_gone_once_the_call_ends() {
        let host = host(vec![], Duration::from_secs(30));

        in_scope(&host, |_scope| ());
        let response = dispatch("{}", |_scope, _request| Ok(json!({})));

        let response: Value = serde_json::from_str(&response).expect("valid json");
        assert_eq!(response["status"], "error", "a finished call's scope outlived it");
        assert_eq!(response["code"], "unavailable");
    }

    #[test]
    fn gives_every_connection_in_a_call_its_own_handle() {
        let (address, port, _accepts) = echo_server(3);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            let mut handles = Vec::new();
            for _ in 0..3 {
                let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
                assert!(!handles.contains(&handle), "two connections in one call shared handle {handle}");
                scope.write(handle, b"ping").expect("the handle addresses a live connection");
                handles.push(handle);
            }
        });
    }

    #[test]
    fn pools_no_more_than_the_configured_number_of_idle_connections() {
        let (address, port, accepts) = echo_server(3);
        let host = Arc::new(SocketHost::new(
            vec![(address.clone(), port)],
            SocketLimits { max_idle_per_endpoint: 1, ..limits(Duration::from_secs(30)) },
        ));

        in_scope(&host, |scope| {
            let (first, _fresh) = scope.open(&address, port, false).expect("opens");
            let (second, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(first, true).expect("releases");
            scope.release(second, true).expect("releases");
        });
        let (from_pool, dialled) = in_scope(&host, |scope| {
            let (_handle, from_pool) = scope.open(&address, port, false).expect("opens");
            let (_handle, dialled) = scope.open(&address, port, false).expect("opens");
            (from_pool, dialled)
        });

        assert!(!from_pool, "the one pooled connection was not reused");
        assert!(dialled, "the pool kept more connections than it was configured to");
        assert_eq!(accepts.recv().expect("first accept"), 1);
        assert_eq!(accepts.recv().expect("second accept"), 2);
        assert_eq!(accepts.recv().expect("third accept"), 3);
    }

    #[test]
    fn refuses_an_operation_once_the_calls_budget_is_spent() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        let error = with_budget(&host, Duration::from_millis(30), |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens inside the budget");
            std::thread::sleep(Duration::from_millis(60));
            scope.write(handle, b"ping").expect_err("the budget is spent")
        });

        assert_eq!(error.code, ErrorCode::Timeout);
    }

    // Without a shared budget, each operation would get the full
    // `io_timeout` and a plugin could chain them past its own deadline.
    #[test]
    fn caps_an_operations_deadline_at_the_remaining_budget() {
        let host = host(vec![], Duration::from_secs(30));

        let (roomy, tight) = (
            with_budget(&host, Duration::from_secs(60), |scope| scope.budget().expect("budget left")),
            with_budget(&host, Duration::from_millis(200), |scope| scope.budget().expect("budget left")),
        );

        assert_eq!(roomy, IO_TIMEOUT, "a roomy call is still capped per operation");
        assert!(tight < IO_TIMEOUT, "a nearly-spent call got a full operation timeout: {tight:?}");
    }

    #[test]
    fn refuses_to_open_more_connections_than_a_call_is_allowed() {
        let (address, port, _accepts) = echo_server(3);
        let host = Arc::new(SocketHost::new(
            vec![(address.clone(), port)],
            SocketLimits { max_open_per_call: 2, ..limits(Duration::from_secs(30)) },
        ));

        let error = in_scope(&host, |scope| {
            scope.open(&address, port, false).expect("first open");
            scope.open(&address, port, false).expect("second open");
            scope.open(&address, port, false).expect_err("third open is over the cap")
        });

        assert_eq!(error.code, ErrorCode::TooManyConnections);
    }

    #[test]
    fn does_not_pool_a_connection_an_operation_failed_on() {
        let (address, port) = silent_server();
        let host = Arc::new(SocketHost::new(
            vec![(address.clone(), port)],
            SocketLimits { io_timeout: Duration::from_millis(50), ..limits(Duration::from_secs(30)) },
        ));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            // The peer never answers, so the read can only time out -- which
            // leaves the connection in an unknown protocol state.
            let error = scope.read(handle, 64).expect_err("the peer never answers");
            assert_eq!(error.code, ErrorCode::Io);
            scope.release(handle, true).expect("releases");
        });

        assert_eq!(host.pooled_count(), 0, "a connection an operation failed on was handed back to the pool");
    }

    // Positive control for the test above: a connection nothing failed on
    // still gets pooled, so the dirty check can't just refuse everything.
    #[test]
    fn pools_a_connection_no_operation_failed_on() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.write(handle, b"ping").expect("writes");
            scope.release(handle, true).expect("releases");
        });

        assert_eq!(host.pooled_count(), 1);
    }

    #[test]
    fn sweeping_drops_connections_idle_past_the_timeout() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_millis(1));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(handle, true).expect("releases");
        });
        std::thread::sleep(Duration::from_millis(20));
        host.sweep_idle();

        assert!(
            host.idle.lock().expect("pool is not poisoned").is_empty(),
            "an endpoint that stopped being used kept its sockets open"
        );
    }

    // Positive control for the sweep: a connection inside its idle timeout
    // survives it, so the sweep can't just empty the pool unconditionally.
    #[test]
    fn sweeping_keeps_a_connection_inside_its_idle_timeout() {
        let (address, port, _accepts) = echo_server(1);
        let host = host(vec![(address.clone(), port)], Duration::from_secs(30));

        in_scope(&host, |scope| {
            let (handle, _fresh) = scope.open(&address, port, false).expect("opens");
            scope.release(handle, true).expect("releases");
        });
        host.sweep_idle();

        assert_eq!(host.pooled_count(), 1);
    }

    #[test]
    fn reports_a_failure_as_data_rather_than_trapping() {
        let host = host(vec![], Duration::from_secs(30));

        let response = in_scope(&host, |_scope| {
            dispatch(r#"{"host":"blocked","port":5432}"#, |scope, request| {
                let request: OpenRequest = parse(request, "sock_open")?;
                let (handle, fresh) = scope.open(&request.host, request.port, request.tls)?;
                Ok(json!({"handle": handle, "fresh": fresh}))
            })
        });

        let response: Value = serde_json::from_str(&response).expect("valid json");
        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "not_allowed", "a plugin must be able to branch on the reason");
        assert!(response["message"].as_str().expect("a message").contains("allowlist"));
    }

    #[test]
    fn refuses_a_socket_operation_outside_a_plugin_call() {
        let response = dispatch("{}", |_scope, _request| Ok(json!({})));

        let response: Value = serde_json::from_str(&response).expect("valid json");
        assert_eq!(response["status"], "error");
    }
}
