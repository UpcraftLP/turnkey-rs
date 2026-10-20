use const_format::formatcp;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const TUBE_APP_ID_LENGTH: usize = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TubeAppID(String);

impl FromStr for TubeAppID {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("App ID cannot be empty!".into());
        }

        if s.len() != TUBE_APP_ID_LENGTH {
            return Err(
                formatcp!("App ID must be exactly {TUBE_APP_ID_LENGTH} ASCII characters!").into(),
            );
        }

        Ok(Self(s.into()))
    }
}

impl Display for TubeAppID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
