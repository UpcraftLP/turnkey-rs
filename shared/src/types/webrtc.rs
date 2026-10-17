use std::str::FromStr;
use chrono::{DateTime, Utc};
use http::Uri;
use rootcause::bail;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebTorrentTrackerSession(#[serde(with = "http_serde::uri")] Uri);

impl FromStr for WebTorrentTrackerSession {
    type Err = rootcause::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::from_str(s)?;

        if uri.scheme_str().is_none_or(|scheme| scheme != "wss") {
            bail!("WebTorrent Tracker URL must start with 'wss://'!");
        }

        Ok(Self(uri))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StunServerSession(String);

impl FromStr for StunServerSession {
    type Err = rootcause::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("stun:") {
            bail!("STUN server address must start with 'stun:'!");
        }

        Ok(Self(s.into()))
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServerSession {
    pub username: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub token: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}