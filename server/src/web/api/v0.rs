mod create_turn_session;

use crate::web::state::AppState;
use axum::Router;
use axum::routing::post;
use huskarl::core::jwk::JwksSource;
use huskarl::core::url_mapping::PublicUrlMapping;
use huskarl_axum::resource_router::ResourceRouter;
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

    let mapping = PublicUrlMapping::new(state.http_frontend_url.as_str(), "/api/v0")
        .context("url mapping failed")?;
    let definition = ResourceDefinition::builder()
        .resource_name("TURN session API")
        .subpath("/api/v0")
        .mapping(mapping.clone())
        .audience(audience)
        .build()
        .context("Unable to create resource definition")?;

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

    let router: Router<()> = Router::new()
        .route(
            "/create-turn-session",
            post(create_turn_session::create_turn_session),
        )
        .with_state(state);

    let authenticated_router = ResourceRouter::new(mapping)
        .register()
        .definition(&definition)
        .validator(validator)
        .routes(router)
        .call()
        .context("Invalid routing registration")?
        .into_router();

    Ok(authenticated_router)
}
