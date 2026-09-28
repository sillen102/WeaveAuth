//! The WeaveAuth plugin contract, and the server side of it for a Rust
//! plugin.
//!
//! A plugin is an ordinary binary. WeaveAuth spawns it, hands it a unix
//! socket path in `WA_PLUGIN_SOCKET`, and calls the [`Plugin`]
//! service over gRPC. Because it's an ordinary process, it keeps its own
//! async runtime, its own connection pools and whatever crates it likes --
//! `tokio-postgres`, `deadpool`, `lapin`, a vendor SDK.
//!
//! ```no_run
//! use weaveauth_plugin_sdk::{
//!     HandleRegistrationRequest, HandleRegistrationResponse, Request, Response, Status, serve,
//! };
//!
//! struct MyPlugin;
//!
//! #[weaveauth_plugin_sdk::async_trait]
//! impl weaveauth_plugin_sdk::Plugin for MyPlugin {
//!     async fn handle_registration(
//!         &self,
//!         request: Request<HandleRegistrationRequest>,
//!     ) -> Result<Response<HandleRegistrationResponse>, Status> {
//!         let registration = request.into_inner();
//!         if registration.fields.get("company").is_none_or(String::is_empty) {
//!             return Err(Status::invalid_argument("company is required"));
//!         }
//!         Ok(Response::new(HandleRegistrationResponse {}))
//!     }
//! }
//!
//! # async fn run() -> Result<(), weaveauth_plugin_sdk::ServeError> {
//! serve(MyPlugin).await
//! # }
//! ```

tonic::include_proto!("weaveauth.plugin");

use std::path::PathBuf;

use plugin_server::PluginServer;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::metadata::MetadataValue;

pub use plugin_server::Plugin;
pub use tonic::{Request, Response, Status, async_trait};

/// Where WeaveAuth tells a plugin to listen. WeaveAuth owns the directory it
/// points into and removes it when the plugin is torn down.
pub const SOCKET_ENV: &str = "WA_PLUGIN_SOCKET";

/// The shared secret WeaveAuth generates at startup and presents on every
/// call. It is regenerated whenever WeaveAuth restarts, and the same value is
/// handed to a plugin that gets restarted under it.
pub const TOKEN_ENV: &str = "WA_PLUGIN_TOKEN";

/// The metadata key [`TOKEN_ENV`]'s value travels in.
pub const TOKEN_METADATA_KEY: &str = "x-weaveauth-token";

/// Returning this from `main` prints it with `Debug`, so `Debug` is the
/// message rather than the variant name -- otherwise a plugin that failed to
/// start reports `NoToken` and leaves its operator guessing.
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
    #[error("{SOCKET_ENV} is not set -- a plugin is spawned by WeaveAuth, which sets it")]
    NoSocketPath,
    #[error("{TOKEN_ENV} is unset or empty -- a plugin is spawned by WeaveAuth, which sets it")]
    NoToken,
    #[error("could not listen on {path}: {source}")]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the plugin server stopped: {0}")]
    Serve(#[from] tonic::transport::Error),
}

/// Serves `plugin` on the socket WeaveAuth assigned, until the process is
/// killed.
///
/// A plugin does not choose its own address: WeaveAuth creates a private
/// directory per plugin process and passes the path in. Every call is checked
/// against the secret in [`TOKEN_ENV`] before it reaches `plugin`, so an
/// implementation cannot forget to do it.
pub async fn serve<P: Plugin>(plugin: P) -> Result<(), ServeError> {
    let path = PathBuf::from(std::env::var_os(SOCKET_ENV).ok_or(ServeError::NoSocketPath)?);
    // A missing *or empty* token is a refusal to start, not a call that skips
    // the check -- an empty one would authenticate every caller that sends an
    // empty header.
    let token = std::env::var(TOKEN_ENV).unwrap_or_default().into_bytes();
    if token.is_empty() {
        return Err(ServeError::NoToken);
    }

    // A restarted plugin inherits the path of the one that died, and bind
    // fails on a leftover file rather than replacing it.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|source| ServeError::Bind { path: path.clone(), source })?;
    tracing::info!(path = %path.display(), "plugin listening");

    tonic::transport::Server::builder()
        .add_service(PluginServer::with_interceptor(plugin, move |request| authenticate(request, &token)))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;
    Ok(())
}

fn authenticate(request: Request<()>, expected: &[u8]) -> Result<Request<()>, Status> {
    let presented = request.metadata().get(TOKEN_METADATA_KEY).map(MetadataValue::as_encoded_bytes);
    match presented {
        Some(presented) if constant_time_eq(presented, expected) => Ok(request),
        // Deliberately the same answer either way: a caller learns whether it
        // holds the secret, not whether it got the length right.
        _ => Err(Status::unauthenticated("caller did not present WeaveAuth's plugin token")),
    }
}

/// Compares in time independent of how much of `a` matches `b`, so a caller
/// can't recover the token a byte at a time. The lengths are not secret --
/// WeaveAuth always generates the same size.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |differing, (x, y)| differing | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(token: Option<&str>) -> Request<()> {
        let mut request = Request::new(());
        if let Some(token) = token {
            request.metadata_mut().insert(TOKEN_METADATA_KEY, token.parse().expect("ascii"));
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

    // The differences have to accumulate, not cancel. Folding them with `^`
    // instead of `|` passes every single-byte-difference case above, and then
    // reports these two equal -- `cargo-mutants` found exactly that.
    #[test]
    fn does_not_let_two_differences_cancel_each_other_out() {
        assert!(!constant_time_eq(b"ab", b"ba"));
        assert!(!constant_time_eq(b"token-AB", b"token-BA"));
    }
}
