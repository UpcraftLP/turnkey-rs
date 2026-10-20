use huskarl::cache::RefreshTokenStore;
use huskarl::core::platform::MaybeSendBoxFuture;
use huskarl::core::{Error, RetryAdvice};
use huskarl::token::RefreshToken;
use rootcause::prelude::ResultExt;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::info;

#[derive(Debug)]
pub struct FileBackedRefreshTokenStore {
    expected_dpop_jkt: String,
    save_file: PathBuf,
}

impl FileBackedRefreshTokenStore {
    pub async fn new(
        save_file: impl AsRef<Path>,
        expected_dpop_jkt: &str,
    ) -> rootcause::Result<Self> {
        let buf = save_file.as_ref().to_path_buf();

        if let Some(parent) = buf.parent() {
            fs::create_dir_all(parent).await.context_with(|| {
                format!(
                    "Unable to create directory: {parent}",
                    parent = parent.display()
                )
            })?;
        }

        Ok(Self {
            expected_dpop_jkt: expected_dpop_jkt.into(),
            save_file: buf,
        })
    }
}

impl RefreshTokenStore for FileBackedRefreshTokenStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        Box::pin(async move {
            if !self.save_file.exists() {
                return Ok(None);
            }

            Ok(None)
        })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let result =
                serde_json::to_string(token).map_err(|e| Error::new(RetryAdvice::No, e))?;
            info!("SET: {result}");

            if token.dpop_jkt().is_none_or(|s| s != self.expected_dpop_jkt) {
                return Err(Error::new(
                    RetryAdvice::No,
                    "DPoP JSON key thumbprint does not match expected value.",
                ));
            }

            fs::write(&self.save_file, &result)
                .await
                .context("unable to create save file")
                .map_err(|e| Error::new(RetryAdvice::No, e))?;
            Ok(())
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            match fs::remove_file(&self.save_file).await {
                Ok(_) => Ok(()),
                Err(e) => match e.kind() {
                    ErrorKind::NotFound => Ok(()),
                    _ => Err(Error::new(RetryAdvice::No, e)),
                },
            }
        })
    }
}
