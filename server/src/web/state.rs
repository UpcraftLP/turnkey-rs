use hmac::digest::CtOutput;
use hmac::{Hmac, KeyInit, Mac};
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl_reqwest::ReqwestClient;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use sha1::Sha1;
use std::env;
use url::Url;

pub(crate) type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub http_frontend_url: Url,
    turn_shared_secret: Vec<u8>,
    pub auth_http_client: ReqwestClient,
    pub auth_metadata: AuthorizationServerMetadata,
}

impl AppState {
    pub(crate) async fn new() -> rootcause::Result<Self> {
        let frontend = env::var("FRONTEND_URL")
            .ok()
            .context("FRONTEND_URL not set!")?;
        let frontend_url: Url = frontend
            .parse()
            .context("FRONTEND_URL was not a valid URL")?;

        let shared_secret = env::var("TURN_SHARED_SECRET")
            .ok()
            .context("TURN_SHARED_SECRET not set!")?;

        let auth_server_url = env::var("OIDC_ISSUER_URL")
            .ok()
            .context("OIDC_ISSUER_URL not set!")?;
        let auth_http_client = ReqwestClient::builder().build().await?;

        let metadata = AuthorizationServerMetadata::oidc_fetch()
            .http_client(&auth_http_client)
            .issuer(auth_server_url)
            .call()
            .await
            .context("Unable to request OIDC configuration from server")?;

        Ok(Self {
            http_frontend_url: frontend_url,
            turn_shared_secret: shared_secret.as_bytes().to_vec(),
            auth_http_client,
            auth_metadata: metadata,
        })
    }

    pub(crate) fn calculate_turn_session_token(
        &self,
        input: impl AsRef<[u8]>,
    ) -> CtOutput<HmacSha1> {
        HmacSha1::new_from_slice(&self.turn_shared_secret)
            .expect("HMAC accepts keys of any size")
            .chain_update(input)
            .finalize()
    }
}
