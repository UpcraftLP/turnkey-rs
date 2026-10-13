mod v0;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

pub(crate) async fn create_router<S>() -> rootcause::Result<Router<S>> {
    Ok(Router::new()
        .route("/", get(|| async { "/api" }))
        .nest("/v0", v0::create_router().await?)
        .with_state(()))
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct ApiResponse<T>
where
    T: Serialize,
{
    data: Option<T>,
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct ApiError<T>
where
    T: Serialize,
{
    #[serde(serialize_with = "crate::web::serialize_status_code")]
    status: StatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

impl<T: Serialize> IntoResponse for ApiError<T> {
    fn into_response(self) -> Response {
        (self.status, Json(self)).into_response()
    }
}
