use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCredentials {
    pub username: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub token: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}
