//! Socket capability wrappers for a WeaveAuth plugin written in Rust.
//!
//! Depend on this crate (`weaveauth-plugin-sdk`, path or git dependency --
//! it isn't published). It turns the four JSON/base64 imports into ordinary
//! functions, so your plugin only writes protocol.

use base64::Engine;
use extism_pdk::*;
use serde::Deserialize;
use serde_json::json;

#[host_fn]
extern "ExtismHost" {
    fn sock_open(request: String) -> String;
    fn sock_write(request: String) -> String;
    fn sock_read(request: String) -> String;
    fn sock_release(request: String) -> String;
}

/// Why a socket operation failed. Match on `code` rather than `message`:
/// the codes are stable, the messages are for logs.
#[derive(Debug, Deserialize)]
pub struct SocketError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for SocketError {}

impl SocketError {
    /// The call's time budget is spent, or the operation hit its deadline.
    /// Retrying inside the same call will not help.
    pub fn is_timeout(&self) -> bool {
        self.code == "timeout"
    }
}

#[derive(Deserialize)]
struct Response {
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    handle: u64,
    #[serde(default)]
    fresh: bool,
    #[serde(default)]
    written: usize,
    #[serde(default)]
    data: String,
    #[serde(default)]
    eof: bool,
}

fn call(host_fn: impl FnOnce(String) -> Result<String, Error>, request: serde_json::Value) -> Result<Response, Error> {
    let response: Response = serde_json::from_str(&host_fn(request.to_string())?)?;
    if response.status != "ok" {
        return Err(SocketError { code: response.code, message: response.message }.into());
    }
    Ok(response)
}

/// A connection the host owns. Dropping it without calling
/// [`Socket::release`] leaves the host to close it -- correct, just not
/// reusable by the next call.
pub struct Socket {
    handle: u64,
    /// `false` when the host handed back a pooled connection, which means
    /// your protocol handshake has already been done on it.
    pub fresh: bool,
}

impl Socket {
    pub fn open(host: &str, port: u16, tls: bool) -> Result<Self, Error> {
        let response = call(|r| unsafe { sock_open(r) }, json!({"host": host, "port": port, "tls": tls}))?;
        Ok(Self { handle: response.handle, fresh: response.fresh })
    }

    pub fn write(&self, data: &[u8]) -> Result<usize, Error> {
        let data = base64::engine::general_purpose::STANDARD.encode(data);
        let response = call(|r| unsafe { sock_write(r) }, json!({"handle": self.handle, "data": data}))?;
        Ok(response.written)
    }

    /// Returns what was available, up to `max` (the host caps a single read
    /// at 1MB). An empty slice means the peer closed the connection.
    pub fn read(&self, max: usize) -> Result<Vec<u8>, Error> {
        let response = call(|r| unsafe { sock_read(r) }, json!({"handle": self.handle, "max": max}))?;
        if response.eof {
            return Ok(Vec::new());
        }
        Ok(base64::engine::general_purpose::STANDARD.decode(&response.data)?)
    }

    /// Reads until `buffer` is full, the way a framed protocol needs.
    pub fn read_exact(&self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(len);
        while buffer.len() < len {
            let chunk = self.read(len - buffer.len())?;
            if chunk.is_empty() {
                return Err(Error::msg("the peer closed the connection mid-message"));
            }
            buffer.extend_from_slice(&chunk);
        }
        Ok(buffer)
    }

    /// Hands the connection back. Pass `reuse: true` **only** when the
    /// connection is back in a clean, reusable protocol state -- mid-protocol
    /// it must be `false`. The host refuses to pool a connection an operation
    /// already failed on, whatever you pass.
    pub fn release(self, reuse: bool) -> Result<(), Error> {
        call(|r| unsafe { sock_release(r) }, json!({"handle": self.handle, "reuse": reuse}))?;
        Ok(())
    }
}
