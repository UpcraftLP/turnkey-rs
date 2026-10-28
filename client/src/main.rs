#[macro_use]
extern crate extension_traits;

mod auth;
pub mod signer;
mod store;

use crate::auth::GrantSource;
use clap::{Parser, Subcommand};
use default_env::default_env;
use directories::ProjectDirs;
use huskarl::core::http::HttpClient;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl::grant::ClientConfiguration;
use huskarl_reqwest::ReqwestClient;
use rootcause::bail;
use rootcause::prelude::ResultExt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Level;
use turnkey_shared::types::tube::TubeAppID;

const OIDC_ISSUER_URL: &str = env!("TURNKEY_OIDC_ISSUER_URL");
const OAUTH_CLIENT_ID: &str = env!("TURNKEY_OIDC_CLIENT_ID");
const TURN_SESSION_SERVER_URL: &str =
    default_env!("TURNKEY_SESSION_SERVER_URL", "http://localhost:5000"); // TODO migrate to stdlib option_env!().unwrap_or() when that becomes const in stable toolchain
const OAUTH_SCOPES: [&str; 4] = ["openid", "profile", "offline_access", "bound_key"];

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
    Login {},
    #[command(name = "create-session")]
    CreateSession {
        #[arg(long)]
        app_id: TubeAppID,
    },
}

#[allow(dead_code)]
struct App<C: HttpClient> {
    dirs: ProjectDirs,

    auth_server_metadata: AuthorizationServerMetadata,
    auth_client_metadata: ClientConfiguration,
    auth_token_source: Arc<GrantSource>,
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
                .with_default_directive(
                    "huskarl=warn"
                        .parse()
                        .context("unable to parse directive")?,
                )
                .from_env_lossy(),
        )
        .with_writer(io::stderr)
        .init();

    // TODO set shared user-agent
    let auth_http_client = ReqwestClient::builder().build().await?;

    let Some(dirs) = ProjectDirs::from("", "", "turnkey-rs") else {
        bail!("Unable to find app data dir")
    };

    let token_save_path = dirs.data_local_dir().join("credentials.bin");

    let (auth_server_metadata, auth_client_metadata, grant_source) = auth::prepare_auth_state(
        OIDC_ISSUER_URL,
        OAUTH_CLIENT_ID,
        token_save_path,
        auth_http_client.clone(),
    )
    .await?;

    let app = App {
        dirs,

        auth_server_metadata,
        auth_client_metadata,
        auth_token_source: Arc::new(grant_source),
        auth_http_client,
    };

    match &cli.command {
        Commands::Login {} => {
            auth::login(&app, OAUTH_SCOPES.map(Into::into).to_vec())
                .await
                .context("Unable to authenticate")?;
        }
        Commands::CreateSession { app_id } => {
            // TODO maybe better error handling here
            if !app
                .auth_token_source
                .can_restore(None)
                .await
                .is_ok_and(|v| v)
            {
                auth::login(&app, OAUTH_SCOPES.map(Into::into).to_vec())
                    .await
                    .context("Unable to authenticate")?;
            }

            auth::create_session(&app, TURN_SESSION_SERVER_URL, app_id)
                .await
                .context("Unable to create session")?;
        }
    }

    Ok(())
}
