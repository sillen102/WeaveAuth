//! Spins up real `backend`/`bff` servers on real (OS-assigned) TCP ports, so
//! a test can drive them over plain HTTP the way they run in production --
//! rather than in-process `oneshot` calls against a stubbed peer.

use std::net::SocketAddr;

/// Binds an ephemeral port and returns it unbound-but-reserved, so its
/// address can be baked into another service's config (e.g. an OIDC
/// provider's registered `redirect_uri`) before that service actually
/// starts serving.
pub async fn reserve_port() -> anyhow::Result<(SocketAddr, tokio::net::TcpListener)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    Ok((addr, listener))
}

pub async fn spawn_backend(
    config: &weaveauth::config::Config,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let (addr, listener) = reserve_port().await?;
    let router = weaveauth::server::app(config).await?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{addr}"), handle))
}

/// Serves `bff` on an already-reserved listener -- used when bff's own
/// address needs to be known (e.g. to register as an OIDC redirect_uri)
/// before backend's config, which is itself needed for bff's `backend_url`,
/// can be built.
pub fn spawn_bff_on(
    listener: tokio::net::TcpListener,
    config: weaveauth_bff::config::Config,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let app = weaveauth_bff::server::app(config)?;
    Ok(tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    }))
}
