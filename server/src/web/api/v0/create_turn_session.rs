use crate::web::api::{ApiError, ApiResponse};
use crate::web::state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::{Duration, SubsecRound, Utc};
use http::StatusCode;
use huskarl_axum::extractors::ValidatedToken;
use std::ops::Add;
use std::sync::Arc;
use turnkey_shared::types::SessionCredentials;

const SESSION_DURATION: Duration = Duration::hours(1);
const BUFFER: Duration = Duration::seconds(7);
pub(crate) async fn create_turn_session(State(state): State<Arc<AppState>>, access_token: ValidatedToken<()>) -> impl IntoResponse {
    let Some(sub) = access_token.sub.clone() else { return ApiError::<()> {
        status: StatusCode::BAD_REQUEST,
        message: Some("Access token missing subject (sub) claim!".into()),
        data: None
    }.into_response() };

    let username = sub;
    let now = Utc::now().trunc_subsecs(0);

    let expiration_time = now.add(SESSION_DURATION).add(BUFFER);
    let username_final = format!(
        "{timestamp}:{username}",
        timestamp = expiration_time.timestamp()
    );

    let token = state
        .calculate_turn_session_token(&username_final)
        .as_bytes()
        .to_vec();

    ApiResponse {
        data: Some(SessionCredentials {
            expires_at: now.add(SESSION_DURATION),
            username: username_final,
            token,
        }),
    }.into_response()
}
