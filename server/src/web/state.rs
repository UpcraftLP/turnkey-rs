use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl_reqwest::ReqwestClient;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::{IteratorExt, ResultExt};
use std::env;
use turnkey_shared::types::webrtc::{StunServerSession, TurnServerInfo, WebTorrentTrackerSession};
use url::Url;

#[derive(Clone)]
pub(crate) struct AppState {
    pub http_frontend_url: Url,
    pub auth_http_client: ReqwestClient,
    pub auth_metadata: AuthorizationServerMetadata,

    pub webtorrent_trackers: Option<Vec<WebTorrentTrackerSession>>,
    pub stun_servers: Option<Vec<StunServerSession>>,
    pub turn_servers: Option<Vec<TurnServerInfo>>
}

impl AppState {
    pub(crate) async fn new() -> rootcause::Result<Self> {
        let frontend = env::var("FRONTEND_URL")
            .ok()
            .context("FRONTEND_URL not set!")?;
        let http_frontend_url: Url = frontend
            .parse()
            .context("FRONTEND_URL was not a valid URL")?;

        let webtorrent_trackers = env::var("WEBTORRENT_TRACKER_URLS")
            .ok()
            .map(|s| s.split(',').into_iter().map(|s| s.parse::<WebTorrentTrackerSession>()).collect_reports_vec()).transpose()
            .context("Unable to parse WEBTORRENT_TRACKER_URLS")?;

        let stun_servers = env::var("STUN_SERVER_URLS")
            .ok()
            .map(|s| s.split(',').into_iter().map(|s| s.parse::<StunServerSession>()).collect_reports_vec()).transpose()
            .context("Unable to parse STUN_SERVER_URLS")?;

        let turn_servers = env::var("TURN_SERVER_URLS")
            .ok()
            .map(|s| s.split(",").into_iter().map(|s| s.parse::<TurnServerInfo>()).collect_reports_vec()).transpose()
            .context("Unable to parse TURN_SERVER_URLS")?;

        let auth_server_url = env::var("OIDC_ISSUER_URL")
            .ok()
            .context("OIDC_ISSUER_URL not set!")?;
        let auth_http_client = ReqwestClient::builder().build().await?;

        let auth_metadata = AuthorizationServerMetadata::oidc_fetch()
            .http_client(&auth_http_client)
            .issuer(auth_server_url)
            .call()
            .await
            .context("Unable to request OIDC configuration from server")?;

        Ok(Self {
            http_frontend_url,
            auth_http_client,
            auth_metadata,

            webtorrent_trackers,
            stun_servers,
            turn_servers,
        })
    }
}
