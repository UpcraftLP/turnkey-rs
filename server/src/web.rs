use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serde::Serializer;

mod api;
mod state;

pub(crate) async fn create_router<S>() -> rootcause::Result<Router<S>> {
    Ok(Router::new()
        .route("/", get(|| async { "/" }))
        .nest("/api", api::create_router().await?)
        .with_state(()))
}

pub(crate) fn serialize_status_code<S: Serializer>(
    value: &StatusCode,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u16(value.as_u16())
}
