use crate::types::crypto::HmacSha1;
use chrono::{DateTime, Utc};
use hmac::digest::CtOutput;
use hmac::{KeyInit, Mac};
use http::Uri;
use rootcause::bail;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::str::FromStr;

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
    pub address: String,
    pub username: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub token: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TurnServerInfo {
    pub address: String,
    pub shared_secret: Vec<u8>
}

impl TurnServerInfo {
    pub fn calculate_session_token(
        &self,
        input: impl AsRef<[u8]>,
    ) -> CtOutput<HmacSha1> {
        HmacSha1::new_from_slice(&self.shared_secret)
            .expect("HMAC accepts keys of any size")
            .chain_update(input)
            .finalize()
    }
}

impl FromStr for TurnServerInfo {
    type Err = rootcause::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("turn:") {
            bail!("Must start with 'turn:'!");
        }

        let mut parts = s.splitn(3, ':').skip(1);
        let Some(address) = parts.next() else { bail!("No address provided!"); };
        let shared_secret = parts.next().unwrap_or_default();

        Ok(Self {
            address: address.into(),
            shared_secret: shared_secret.into(),
        })
    }
}