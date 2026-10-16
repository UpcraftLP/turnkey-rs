mod create_turn_session;

use crate::web::state::AppState;
use axum::Router;
use axum::routing::{get, post};
use huskarl_axum::layers::ValidatorLayer;
use huskarl_resource_server::validator::custom::CustomValidator;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use std::env;
use std::sync::Arc;

pub(crate) async fn create_router() -> rootcause::Result<Router> {
    let state = Arc::new(AppState::new().await.context("Unable to create AppState")?);

    // TODO move into state
    let audience_str = env::var("OIDC_AUDIENCE")
        .ok()
        .context("OIDC_AUDIENCE not set!")?;

    // TODO authentik does not currently support DPoP for access tokens, only ID tokens
    // A stable AEAD key, shared by every replica (32 base64 bytes). XChaCha20-
    // Poly1305 suits a long-lived, unbounded-use seal key like this one.
    // let nonce_key = XChaChaKey::from_secret(
    //     EnvVarSecret::new("DPOP_NONCE_KEY", &Base64Encoding)?.mapped(OctBytes::new("XC20P")),
    // ).await?;

    let validator = CustomValidator::builder_from_metadata(&state.auth_metadata)
        .iss(state.auth_metadata.issuer.clone())
        .aud(audience_str)
        .jwks_source(state.auth_http_client.clone())
        // .require_dpop(true)
        // .dpop_nonce_checker(
        //     SealedTimestampNonce::builder()
        //         .sealer(AeadV1Sealer::new(nonce_key))
        //         .build()
        // )
        .build()
        .await
        .context("Unable to create resource validator")?;

    let validator_layer = ValidatorLayer::builder()
        .validator(validator)
        .base_url(&state.http_frontend_url)
        .context("unable to build resource validator layer")?
        .build();

    let require_auth = validator_layer.require_authenticated();

    Ok(Router::new()
        .route("/", get(|| async { "/api/v0" }))
        .route(
            "/create-turn-session",
            post(create_turn_session::create_turn_session).layer(require_auth),
        )
        .layer(validator_layer)
        .with_state(state))
}
