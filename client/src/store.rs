use crate::credentials::OAuthCredentials;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub(crate) struct StoredCredentials {}

impl StoredCredentials {
    pub(crate) async fn save(&self, file: impl AsRef<Path>) -> rootcause::Result<()> {
        todo!("implement saving")
    }

    pub(crate) async fn load(file: impl AsRef<Path>) -> rootcause::Result<Option<Self>> {
        todo!("implement loading")
    }
}

impl From<OAuthCredentials> for StoredCredentials {
    fn from(value: OAuthCredentials) -> Self {
        todo!("implement serialization")
    }
}
