mod auth;
mod credentials;
mod store;

use clap::{Parser, Subcommand};
use huskarl::core::http::HttpClient;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use rootcause::prelude::ResultExt;
use std::path::PathBuf;

use huskarl_reqwest::ReqwestClient;
use tracing::Level;

// TODO set during build
const OIDC_ISSUER_URL: &str = env!("TURNKEY_OIDC_ISSUER_URL");
const OAUTH_CLIENT_ID: &str = env!("TURNKEY_OIDC_CLIENT_ID");
const OAUTH_SCOPES: &str = env!("TURNKEY_OAUTH_SCOPES");
const TURN_SESSION_SERVER_URL: &str = env!("TURNKEY_SESSION_SERVER_URL");

// TODO store refresh token with salt
const CREDENTIALS_SALT: &str = "";

fn get_oauth_scopes() -> Vec<String> {
    OAUTH_SCOPES.split(',').map(Into::into).collect()
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    credentials_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {}

struct App<C: HttpClient> {
    auth_metadata: AuthorizationServerMetadata,
    auth_http_client: C,
}

#[tokio::main]
async fn main() -> rootcause::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(Level::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Args::try_parse().context("Unable to parse CLI arguments")?;

    // TODO set shared user-agent
    let http_client = ReqwestClient::builder().build().await?;

    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(OIDC_ISSUER_URL)
        .call()
        .await
        .context("Unable to request OIDC configuration from server")?;

    let app = App {
        auth_http_client: http_client,
        auth_metadata: metadata,
    };

    auth::login(&app).await.context("Unable to authenticate")?;

    // TODO configure DPoP
    // https://github.com/huskarl-rs/huskarl/blob/main/huskarl/docs/guide/dpop.md

    // let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    //     .client_id(OAUTH_CLIENT_ID)
    //     .http_client(http_client.clone())
    //     .client_auth(NoAuth)
    //     .build();
    //
    // let parameters = ClientCredentialsGrantParameters::builder()
    //     .build();
    // let response = grant.exchange(parameters).await
    //     .context("Unable to obtain token from auth server")?;
    //
    // info!("Access token: {}", response.access_token().token().expose_secret());
    // info!("Has refresh token: {}", response.refresh_token().is_some());

    // step 4: save current auth/refresh tokens
    // step 5: call create TURN session endpoint
    // step 6: valiadte and return payload json
    Ok(())
}
