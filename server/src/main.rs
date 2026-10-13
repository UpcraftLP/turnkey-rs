use axum::Router;
use rootcause::prelude::ResultExt;
use std::env;
use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{Level, info};

mod web;

const SERVER_PORT: u16 = 5000;

#[dotenvy::load(required = false)]
#[tokio::main]
async fn main() -> rootcause::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(Level::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let app: Router = web::create_router()
        .await
        .context("Unable to set up routing context")?
        .layer(TraceLayer::new_for_http());
    let addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), SERVER_PORT);
    let listener = TcpListener::bind(addr)
        .await
        .context_with(|| format!("Unable to bind to port {SERVER_PORT}"))?;

    let server_addr = env::var("FRONTEND_URL")
        .ok()
        .unwrap_or_else(|| format!("http://localhost:{SERVER_PORT}"));
    info!("Listening on {server_addr} ({addr})");
    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown_signal())
        .await?;

    Ok(())
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        biased;
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating shutdown");
        }
    }
}
