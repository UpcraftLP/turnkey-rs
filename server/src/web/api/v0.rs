mod create_turn_session;

use crate::web::state::AppState;
use axum::Router;
use axum::routing::{get, post};
use huskarl::core::jwk::JwksSource;
use huskarl::core::url_mapping::PublicUrlMapping;
use huskarl_axum::layers::ValidatorLayer;
use huskarl_resource_server::resource::{AudienceBinding, ResourceDefinition};
use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use std::env;
use std::sync::Arc;

pub(crate) async fn create_router() -> rootcause::Result<Router> {
    let state = Arc::new(AppState::new().await.context("Unable to create AppState")?);

    let audience_str = env::var("OIDC_AUDIENCE")
        .ok()
        .context("OIDC_AUDIENCE not set!")?;
    let audience = AudienceBinding::mapped([audience_str.clone()]);

    // this doesn't actually seem to be used. huskarl-axum bug?
    // let mapping = PublicUrlMapping::new(state.http_frontend_url.clone().as_str(), "/")
    //     .context("url mapping failed")?;

    // let definition = ResourceDefinition::builder()
    //     .resource_name("TURN session API")
    //     .subpath("/")
    //     .mapping(mapping)
    //     .audience(audience)
    //     .build()
    //     .context("Unable to create resource definition")?;

    let validator = Rfc9068Validator::builder_from_metadata(&state.auth_metadata)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(state.auth_http_client.clone())
                .build(),
        ))
        .audience(audience_str)
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
