use crate::store::StoredCredentials;
use std::path::Path;

pub(crate) struct OAuthCredentials {}

pub(crate) async fn get_credentials(
    credentials_file: impl AsRef<Path>,
) -> rootcause::Result<OAuthCredentials> {
    if let Some(credentials) = StoredCredentials::load(credentials_file).await? {
        // TODO step 1: load auth token, if valid: skip login
        // TODO step 2: obtain new auth token using refresh token, if success skip login
    }

    // step 3: [LOGIN] create new auth/refresh tokens, using webview
    todo!()
}

async fn refresh_credentials() {}

async fn login() -> rootcause::Result<OAuthCredentials> {
    todo!()
}
