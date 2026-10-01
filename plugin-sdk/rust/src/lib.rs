//! The WeaveAuth plugin contract, and the server side of it for a Rust
//! plugin.
//!
//! A plugin is an ordinary binary. WeaveAuth spawns it with one end of a
//! connected unix socket as its stdin, writes a secret token as the first
//! line on it, and then calls the [`Plugin`] service over it with gRPC.
//! Because it's an ordinary process, it keeps its own async runtime, its own
//! connection pools and whatever crates it likes -- `tokio-postgres`,
//! `deadpool`, `lapin`, a vendor SDK.
//!
//! One generic rpc, [`Plugin::invoke`], serves every flow -- `request.hook`
//! says which one, so adding a flow (registration, login claims, an email
//! notification, ...) is a new hook name a plugin recognizes, not a new rpc.
//!
//! ```no_run
//! use weaveauth_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status, serve};
//!
//! struct MyPlugin;
//!
//! #[weaveauth_plugin_sdk::async_trait]
//! impl weaveauth_plugin_sdk::Plugin for MyPlugin {
//!     async fn invoke(&self, request: Request<PluginRequest>) -> Result<Response<PluginResponse>, Status> {
//!         let request = request.into_inner();
//!         match request.hook.as_str() {
//!             "registration" => {
//!                 let has_company = request.data.as_ref().is_some_and(|data| data.fields.contains_key("company"));
//!                 if !has_company {
//!                     // Rejecting fails the whole registration; no user is created.
//!                     return Err(Status::invalid_argument("company is required"));
//!                 }
//!                 Ok(Response::new(PluginResponse { data: None }))
//!             }
//!             other => Err(Status::unimplemented(format!("unhandled hook {other:?}"))),
//!         }
//!     }
//! }
//!
//! # async fn run() -> Result<(), weaveauth_plugin_sdk::ServeError> {
//! serve(MyPlugin).await
//! # }
//! ```

tonic::include_proto!("weaveauth.plugin");

use std::io::Read;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use plugin_server::PluginServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;

pub use plugin_server::Plugin;
pub use tonic::{Request, Response, Status, async_trait};

/// The metadata key WeaveAuth presents its token in on every call. The token
/// itself is the first line WeaveAuth writes on the connection, before any
/// gRPC traffic: a secret generated at startup and handed to every restart
/// of the plugin.
pub const TOKEN_METADATA_KEY: &str = "x-weaveauth-token";

/// Longest token line read before giving up. WeaveAuth's is 43 characters;
/// the cap only stops a stray stream from being read forever.
const MAX_TOKEN_LINE: usize = 256;

/// Returning this from `main` prints it with `Debug`, so `Debug` is the
/// message rather than the variant name -- otherwise a plugin that failed to
/// start reports `NotSpawnedByWeaveAuth` and leaves its operator guessing.
impl std::fmt::Debug for ServeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self}")?;
        let mut source = std::error::Error::source(self);
        while let Some(error) = source {
            write!(formatter, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}

#[derive(thiserror::Error)]
pub enum ServeError {
    #[error(
        "stdin is not a unix socket -- a plugin is spawned by WeaveAuth, which connects it there"
    )]
    NotSpawnedByWeaveAuth(#[source] std::io::Error),
    #[error("could not read the token from the connection: {0}")]
    ReadToken(#[source] std::io::Error),
    #[error("no token on the connection -- WeaveAuth writes one before its first call")]
    NoToken,
    #[error("could not point stdin at /dev/null: {0}")]
    ReleaseStdin(#[source] std::io::Error),
    #[error("the plugin server stopped: {0}")]
    Serve(#[from] tonic::transport::Error),
}

/// Serves `plugin` on the connection WeaveAuth handed over as stdin, and
/// returns once WeaveAuth closes it -- when WeaveAuth stops, drops this
/// plugin, or the connection breaks. Returning from `main` then is what ends
/// the process: WeaveAuth usually runs as another user, so it can't kill it.
///
/// There is no address: stdin is one end of a socket pair WeaveAuth created,
/// so WeaveAuth is the only process that can call the plugin. On top of
/// that, every call is checked against the token before it reaches `plugin`,
/// so an implementation cannot forget to do it. Stdin itself is pointed at
/// `/dev/null` once the connection is taken, so a subprocess can't inherit it.
pub async fn serve<P: Plugin>(plugin: P) -> Result<(), ServeError> {
    let stream = socket_on_stdin().map_err(ServeError::NotSpawnedByWeaveAuth)?;
    let dev_null = std::fs::File::open("/dev/null").map_err(ServeError::ReleaseStdin)?;
    rustix::stdio::dup2_stdin(&dev_null).map_err(|errno| ServeError::ReleaseStdin(errno.into()))?;
    serve_on(stream, plugin).await
}

/// [`serve`] on an already-taken connection, so it can run without a process
/// whose stdin is a socket.
async fn serve_on<P: Plugin>(
    mut stream: std::os::unix::net::UnixStream,
    plugin: P,
) -> Result<(), ServeError> {
    // A missing *or empty* token is a refusal to start, not a call that skips
    // the check -- an empty one would authenticate every caller that sends an
    // empty header.
    let token = read_token(&mut stream).map_err(ServeError::ReadToken)?;
    if token.is_empty() {
        return Err(ServeError::NoToken);
    }
    stream
        .set_nonblocking(true)
        .map_err(ServeError::NotSpawnedByWeaveAuth)?;
    let (watched, closed) =
        Watched::new(UnixStream::from_std(stream).map_err(ServeError::NotSpawnedByWeaveAuth)?);
    tracing::info!("plugin serving on stdin");

    // The one connection is all there is: once it has been handed over, the
    // server waits for `closed` instead of shutting down for want of another.
    let incoming =
        tokio_stream::once(Ok::<_, std::io::Error>(watched)).chain(tokio_stream::pending());
    tonic::transport::Server::builder()
        .add_service(PluginServer::with_interceptor(plugin, move |request| {
            authenticate(request, &token)
        }))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = closed.await;
        })
        .await?;
    tracing::info!("WeaveAuth closed the connection, stopping");
    Ok(())
}

/// The connection, plus a sender dropped along with it: hyper drops the IO
/// when its connection ends, and that is how [`serve`] learns WeaveAuth is
/// gone.
struct Watched {
    stream: UnixStream,
    _closed: oneshot::Sender<()>,
}

impl Watched {
    fn new(stream: UnixStream) -> (Self, oneshot::Receiver<()>) {
        let (sender, closed) = oneshot::channel();
        (
            Self {
                stream,
                _closed: sender,
            },
            closed,
        )
    }
}

impl AsyncRead for Watched {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for Watched {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

fn socket_on_stdin() -> std::io::Result<std::os::unix::net::UnixStream> {
    let stream =
        std::os::unix::net::UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    // Fails with ENOTSOCK on a terminal, a pipe or /dev/null.
    stream.local_addr()?;
    Ok(stream)
}

/// Reads the first line one byte at a time: anything past the newline is
/// already gRPC, and has to be left on the socket for the server.
fn read_token(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < MAX_TOKEN_LINE {
        if stream.read(&mut byte)? == 0 || byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("the token line is longer than {MAX_TOKEN_LINE} bytes"),
    ))
}

fn authenticate(request: Request<()>, expected: &[u8]) -> Result<Request<()>, Status> {
    let presented = request
        .metadata()
        .get(TOKEN_METADATA_KEY)
        .map(MetadataValue::as_encoded_bytes);
    match presented {
        Some(presented) if constant_time_eq(presented, expected) => Ok(request),
        // Deliberately the same answer either way: a caller learns whether it
        // holds the secret, not whether it got the length right.
        _ => Err(Status::unauthenticated(
            "caller did not present WeaveAuth's plugin token",
        )),
    }
}

/// Compares in time independent of how much of `a` matches `b`, so a caller
/// can't recover the token a byte at a time. The lengths are not secret --
/// WeaveAuth always generates the same size.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .fold(0u8, |differing, (x, y)| differing | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(token: Option<&str>) -> Request<()> {
        let mut request = Request::new(());
        if let Some(token) = token {
            request
                .metadata_mut()
                .insert(TOKEN_METADATA_KEY, token.parse().expect("ascii"));
        }
        request
    }

    #[test]
    fn accepts_a_call_presenting_the_expected_token() {
        assert!(authenticate(request_with(Some("s3cret")), b"s3cret").is_ok());
    }

    #[test]
    fn rejects_a_call_presenting_the_wrong_token() {
        assert!(authenticate(request_with(Some("wrong")), b"s3cret").is_err());
    }

    // The case that matters most: a caller that simply omits the metadata must
    // not fall through to the service.
    #[test]
    fn rejects_a_call_presenting_no_token_at_all() {
        assert!(authenticate(request_with(None), b"s3cret").is_err());
    }

    // A prefix of the real token must not pass -- the comparison is over the
    // whole value, not "starts with".
    #[test]
    fn rejects_a_token_that_is_only_a_prefix_of_the_expected_one() {
        assert!(authenticate(request_with(Some("s3c")), b"s3cret").is_err());
    }

    #[test]
    fn compares_every_byte() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    // Whatever follows the newline is the client's HTTP/2 preface; reading
    // one byte too many would corrupt the connection.
    #[test]
    fn reads_the_token_line_and_not_a_byte_further() {
        let mut stream: &[u8] = b"s3cret\nPRI * HTTP/2.0";

        assert_eq!(read_token(&mut stream).expect("reads"), b"s3cret");
        assert_eq!(stream, b"PRI * HTTP/2.0");
    }

    // Reported as too long, not as missing: the two point at different bugs.
    #[test]
    fn refuses_a_token_line_that_never_ends() {
        let mut stream: &[u8] = &[b'a'; MAX_TOKEN_LINE + 1];

        let error = read_token(&mut stream).expect_err("an endless line is not a token");

        assert!(
            error.to_string().contains("longer than"),
            "unhelpful error: {error}"
        );
    }

    // The differences have to accumulate, not cancel. Folding them with `^`
    // instead of `|` passes every single-byte-difference case above, and then
    // reports these two equal -- `cargo-mutants` found exactly that.
    #[test]
    fn does_not_let_two_differences_cancel_each_other_out() {
        assert!(!constant_time_eq(b"ab", b"ba"));
        assert!(!constant_time_eq(b"token-AB", b"token-BA"));
    }

    struct Unimplemented;

    #[async_trait]
    impl Plugin for Unimplemented {
        async fn invoke(
            &self,
            _: Request<PluginRequest>,
        ) -> Result<Response<PluginResponse>, Status> {
            Err(Status::unimplemented("test plugin"))
        }
    }

    async fn serve_after_writing(first_bytes: &[u8]) -> Result<(), ServeError> {
        use std::io::Write;
        let (server_end, mut client_end) =
            std::os::unix::net::UnixStream::pair().expect("socket pair");
        client_end.write_all(first_bytes).expect("writes");
        drop(client_end);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve_on(server_end, Unimplemented),
        )
        .await
        .expect("serve_on returns once the connection is closed")
    }

    // An empty token would authenticate every caller that sends an empty header.
    #[tokio::test]
    async fn refuses_to_start_on_an_empty_token() {
        assert!(matches!(
            serve_after_writing(b"\n").await,
            Err(ServeError::NoToken)
        ));
    }

    #[tokio::test]
    async fn refuses_to_start_when_the_connection_closes_before_a_token() {
        assert!(matches!(
            serve_after_writing(b"").await,
            Err(ServeError::NoToken)
        ));
    }

    #[tokio::test]
    async fn refuses_to_start_on_a_token_line_that_never_ends() {
        let endless = vec![b'a'; MAX_TOKEN_LINE + 1];
        assert!(matches!(
            serve_after_writing(&endless).await,
            Err(ServeError::ReadToken(_))
        ));
    }

    // Companion to the refusals above: a valid token must start the server,
    // which then returns Ok once WeaveAuth closes the connection.
    #[tokio::test]
    async fn serves_until_the_connection_closes() {
        assert!(serve_after_writing(b"s3cret\n").await.is_ok());
    }
}
