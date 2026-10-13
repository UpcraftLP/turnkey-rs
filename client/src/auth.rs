use crate::{App, OAUTH_CLIENT_ID, TURN_SESSION_SERVER_URL};
use chrono::{DateTime, Utc};
use http::Uri;
use huskarl::authorizer::HttpAuthorizer;
use huskarl::cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource};
use huskarl::core::client_auth::NoAuth;
use huskarl::core::dpop::DPoP;
use huskarl::core::http::HttpClient;
use huskarl::grant::authorization_code::{
    AuthorizationCodeGrant, Display, StartInput, StartOutput, bind_loopback,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use reqwest::{Client, Method};
use rootcause::prelude::ResultExt;
use std::str::FromStr;
use tracing::info;
use url::Url;

pub(crate) async fn login<C: HttpClient + Clone + 'static>(app: &App<C>) -> rootcause::Result<()> {
    let listener = bind_loopback(0)
        .await
        .context("Failed to bind auth callback listener")?;

    let dpop_key = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .context("Failed to generate DPoP key")?;

    let grant = AuthorizationCodeGrant::builder_from_metadata(&app.auth_metadata)
        .context("Authorization server does not support authorization code grant")?
        .client_id(OAUTH_CLIENT_ID)
        .http_client(app.auth_http_client.clone())
        .client_auth(NoAuth)
        .redirect_uri(format!(
            "http://{addr}/login/callback",
            addr = listener
                .local_addr()
                .context("Unable to get callback address")?
        ))
        .dpop(DPoP::builder().signer(dpop_key).build())
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
                .scope(crate::get_oauth_scopes())
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
    info!("Authorization URL: {authorization_url}");

    // TODO custom CallbackRenderer to customize HTML that is shown to the user
    let completed = grant
        .complete_on_loopback(&listener, &pending_state, None)
        .await
        .context("Unable to get auth token")?;

    // info!("ID Token: {:?}", completed.id_token);

    let token_source = GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(NoSource)
        .refresh_store(InMemoryRefreshTokenStore::default())
        .build();

    token_source
        .prime(completed.token_response)
        .await
        .context("Unable to prime token source")?;

    let authorizer = HttpAuthorizer::builder()
        .cache(InMemoryTokenCache::builder().source(token_source).build())
        .build();

    let endpoint_url = Url::parse(TURN_SESSION_SERVER_URL)
        .and_then(|it| it.join("api/v0/create-turn-session"))
        .context("Unable to create TURN session endpoint URL")?;

    let headers = authorizer
        .get_headers(&Method::POST, &Uri::from_str(endpoint_url.as_ref())?)
        .await
        .context("Failed to create auth headers")?;

    // TODO user agent
    let rq_client = Client::builder().build()?;

    let response = rq_client.post(endpoint_url).headers(headers).send().await?;
    let txt = response.text().await?;

    info!("Received:\n{txt}");

    Ok(())
}
