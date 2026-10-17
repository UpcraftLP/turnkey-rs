use crate::types::tube::TubeAppID;
use crate::types::webrtc::{StunServerSession, TurnServerSession, WebTorrentTrackerSession};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionInput {
    pub app_id: TubeAppID,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webtorrent_trackers: Option<Vec<WebTorrentTrackerSession>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_servers: Option<Vec<StunServerSession>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_servers: Option<Vec<TurnServerSession>>,
}