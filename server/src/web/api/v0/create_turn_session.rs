use crate::web::api::{ApiError, ApiResponse};
use crate::web::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::{Duration, SubsecRound, Utc};
use http::StatusCode;
use huskarl_axum::extractors::ValidatedToken;
use std::ops::Add;
use std::sync::Arc;
use tracing::info;
use turnkey_shared::types::session::{CreateSessionInput, CreateSessionResponse};
use turnkey_shared::types::webrtc::TurnServerSession;

const SESSION_DURATION: Duration = Duration::hours(1);
const BUFFER: Duration = Duration::seconds(7);

pub(crate) async fn create_turn_session(State(state): State<Arc<AppState>>, access_token: ValidatedToken<()>, Json(input): Json<CreateSessionInput>) -> impl IntoResponse {
    let Some(username) = access_token.sub.clone() else { return ApiError::<()> {
        status: StatusCode::BAD_REQUEST,
        message: Some("Access token missing subject (sub) claim!".into()),
        data: None
    }.into_response() };

    let now = Utc::now().trunc_subsecs(0);

    let expiration_time = now.add(SESSION_DURATION).add(BUFFER);
    let username_final = format!(
        "{timestamp}:{username}",
        timestamp = expiration_time.timestamp()
    );

    let turn_servers = state.turn_servers.as_ref().map(|vec| vec.iter().map(|server_info| {
        let token = server_info
            .calculate_session_token(&username_final)
            .as_bytes()
            .to_vec();

        TurnServerSession {
            address: server_info.address.clone(),
            expires_at: expiration_time,
            username: username_final.clone(),
            token,
        }
    }).collect::<Vec<_>>());

    info!("Created new session for user: '{username}', app_id: '{app_id}'", app_id = input.app_id);

    ApiResponse {
        data: Some(CreateSessionResponse {
            app_id: Some(input.app_id),
            webtorrent_trackers: state.webtorrent_trackers.clone(),
            stun_servers: state.stun_servers.clone(),
            turn_servers,
        }),
    }.into_response()
}
