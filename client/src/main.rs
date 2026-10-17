#[macro_use]
extern crate extension_traits;

mod auth;
mod credentials;
mod store;

use clap::{Parser, Subcommand};
use huskarl::core::http::HttpClient;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl_reqwest::ReqwestClient;
use rootcause::prelude::ResultExt;
use std::io;
use std::path::PathBuf;
use default_env::default_env;
use tracing::Level;
use turnkey_shared::types::tube::TubeAppID;

// TODO set during build
const OIDC_ISSUER_URL: &str = env!("TURNKEY_OIDC_ISSUER_URL");
const OAUTH_CLIENT_ID: &str = env!("TURNKEY_OIDC_CLIENT_ID");
const TURN_SESSION_SERVER_URL: &str = default_env!("TURNKEY_SESSION_SERVER_URL", "http://localhost:5000"); // TODO migrate to stdlib option_env!().unwrap_or() when that becomes const in stable toolchain
const OAUTH_SCOPES: [&str; 4] = ["openid", "profile", "offline_access", "bound_key"];

// TODO store refresh token with salt
const CREDENTIALS_SALT: &str = "";

fn get_oauth_scopes() -> Vec<String> {
    OAUTH_SCOPES.map(Into::into).to_vec()
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    credentials_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    disable_ansi: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Login { },
    #[command(name = "create-session")]
    CreateSession {
        #[arg(long)]
        app_id: TubeAppID,
    }
}

struct App<C: HttpClient> {
    auth_metadata: AuthorizationServerMetadata,
    auth_http_client: C,
}

#[tokio::main]
async fn main() -> rootcause::Result<()> {
    let cli = Args::parse();

    tracing_subscriber::fmt()
        .with_ansi(!cli.disable_ansi)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(io::stderr)
        .init();

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

    match &cli.command {
        Commands::Login { } => {
            auth::login(&app).await.context("Unable to authenticate")?;
        }
        Commands::CreateSession { app_id } => {
            let authorizer = auth::login(&app).await.context("Unable to authenticate")?;
            auth::create_session(&app, authorizer, app_id).await.context("Unable to create session")?;
        }
    }

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
