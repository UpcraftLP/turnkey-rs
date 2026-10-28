use crate::App;
use crate::signer::{DEFAULT_KEY_NAME, TpmDPoPSelector, TpmDPoPSigner};
use crate::store::FileBackedRefreshTokenStore;
use chrono::{DateTime, Utc};
use hardware_enclave::AccessPolicy;
use http::Uri;
use huskarl::authorizer::HttpAuthorizer;
use huskarl::cache::{GrantTokenSource, InMemoryTokenCache, NoSource};
use huskarl::core::client_auth::NoAuth;
use huskarl::core::crypto::signer::AsymmetricJwsSigner;
use huskarl::core::dpop::DPoP;
use huskarl::core::http::HttpClient;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl::grant::ClientConfiguration;
use huskarl::grant::authorization_code::{
    AuthorizationCodeGrant, Display, StartInput, StartOutput, bind_loopback,
};
use huskarl::grant::refresh::RefreshGrant;
use reqwest::{Client, Method};
use rootcause::prelude::ResultExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::path::Path;
use std::str::FromStr;
use tracing::info;
use turnkey_shared::types::session::CreateSessionInput;
use turnkey_shared::types::tube::TubeAppID;
use url::Url;

pub(crate) type GrantSource = GrantTokenSource<RefreshGrant, FileBackedRefreshTokenStore>;

pub(crate) async fn prepare_auth_state<C: HttpClient + Clone + 'static>(
    oidc_issuer_url: &str,
    oauth_client_id: &str,
    token_save_path: impl AsRef<Path>,
    auth_http_client: C,
) -> rootcause::Result<(
    AuthorizationServerMetadata,
    ClientConfiguration,
    GrantSource,
)> {
    let auth_server_metadata = AuthorizationServerMetadata::oidc_fetch()
        .issuer(oidc_issuer_url)
        .http_client(&auth_http_client)
        .call()
        .await
        .context("Unable to request OIDC configuration from server")?;

    let dpop_signer = TpmDPoPSigner::new(DEFAULT_KEY_NAME, AccessPolicy::None)
        .context("Unable to load TPM key")?;

    let dpop_jkt = dpop_signer.public_key_jwk().thumbprint();

    let auth_client_metadata = ClientConfiguration::builder()
        .client_id(oauth_client_id)
        .client_auth(NoAuth)
        .dpop(
            DPoP::builder()
                .signer(TpmDPoPSelector::new(dpop_signer))
                .build(),
        )
        .build();

    let token_store = FileBackedRefreshTokenStore::new(token_save_path, &dpop_jkt).await?;

    let grant = RefreshGrant::builder_from_metadata(&auth_server_metadata)
        .client(&auth_client_metadata)
        .http_client(auth_http_client)
        .build();

    let grant_source = GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(NoSource)
        .refresh_store(token_store)
        .build();

    Ok((auth_server_metadata, auth_client_metadata, grant_source))
}

pub(crate) async fn login<C: HttpClient + Clone + 'static>(
    state: &App<C>,
    oauth_scopes: Vec<String>,
) -> rootcause::Result<()> {
    let listener = bind_loopback(0)
        .await
        .context("Failed to bind auth callback listener")?;

    let grant = AuthorizationCodeGrant::builder_from_metadata(&state.auth_server_metadata)
        .context("Authorization server does not support authorization code grant")?
        .client(&state.auth_client_metadata)
        .http_client(state.auth_http_client.clone())
        .redirect_uri(format!(
            "http://{addr}/login/callback",
            addr = listener
                .local_addr()
                .context("Unable to get callback address")?
        ))
        .build()
        .await
        .context("Failed to build authorization grant")?;

    let StartOutput {
        authorization_url,
        expires_at,
        pending_state,
        ..
    } = grant
        .start(
            StartInput::builder()
                .scope(oauth_scopes)
                .display(Display::Popup)
                .build(),
        )
        .await
        .context("Failed to retrieve authorization URL")?;

    info!("Auth challenge received!");
    if let Some(exp) = expires_at {
        let dt: DateTime<Utc> = exp.into();
        info!("Expires at: {dt}");
    }

    // TODO turn this into webview instead
    webbrowser::open(&authorization_url.to_string())
        .context("Unable to open authorization URL in browser")?;

    // TODO custom CallbackRenderer to customize HTML that is shown to the user
    let completed = grant
        .complete_on_loopback(&listener, &pending_state, None)
        .await
        .context("Unable to get auth token")?;

    state
        .auth_token_source
        .prime(completed.token_response)
        .await
        .context("Unable to prime grant token source")?;

    Ok(())
}

pub async fn create_session<C: HttpClient + Clone + 'static>(
    state: &App<C>,
    session_server_url: &str,
    app_id: &TubeAppID,
) -> rootcause::Result<()> {
    let authorizer = HttpAuthorizer::builder()
        .cache(
            InMemoryTokenCache::builder()
                .source(state.auth_token_source.clone())
                .build(),
        )
        .build();

    let endpoint_url = Url::parse(session_server_url)
        .and_then(|it| it.join("api/v0/create-turn-session"))
        .context("Unable to create TURN session endpoint URL")?;

    let headers = authorizer
        .get_headers(&Method::POST, &Uri::from_str(endpoint_url.as_ref())?)
        .await
        .context("Failed to create auth headers")?;

    // TODO user agent
    let rq_client = Client::builder().build()?;

    let response = rq_client
        .post(endpoint_url)
        .headers(headers)
        .json(&CreateSessionInput {
            app_id: app_id.clone(),
        })
        .send()
        .await
        .context("Failed to send TURN session API request")?;
    let status = response.status().as_u16();

    let parsed: Value = response
        .error_for_status()
        .context_with(|| format!("Received status code {status}"))?
        .json_with_error()
        .await
        .context("Unable to read response body")?;

    serde_json::to_writer(std::io::stdout(), &parsed)
        .context("Unable to serialize API response")?;

    Ok(())
}

#[extension(pub(crate) trait BetterJsonError)]
impl reqwest::Response {
    async fn json_with_error<T>(self) -> rootcause::Result<T>
    where
        T: DeserializeOwned,
    {
        let url = self.url().clone();
        let content = self
            .bytes()
            .await
            .context_with(|| format!("Unable to read response body for {url}"))?;
        let reader = &mut serde_json::Deserializer::from_slice(&content);
        let json = serde_path_to_error::deserialize(reader)
            .context_with(|| format!("Unable to decode response for {url}"))?;

        Ok(json)
    }
}
