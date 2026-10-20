use huskarl::cache::RefreshTokenStore;
use huskarl::core::platform::MaybeSendBoxFuture;
use huskarl::core::{Error, RetryAdvice};
use huskarl::token::RefreshToken;
use rootcause::prelude::ResultExt;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

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
            fs::create_dir_all(parent).context_with(|| {
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
            match File::open(&self.save_file) {
                Ok(file) => {
                    let token: RefreshToken = serde_json::from_reader(file)
                        .context("Unable to parse stored refresh token")
                        .map_err(|e| Error::new(RetryAdvice::No, e))?;
                    Ok(Some(token))
                }
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        return Ok(None);
                    }

                    Err(Error::new(RetryAdvice::No, e))
                }
            }
        })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            if token.dpop_jkt().is_none_or(|s| s != self.expected_dpop_jkt) {
                return Err(Error::new(
                    RetryAdvice::No,
                    "DPoP JSON key thumbprint does not match expected value.",
                ));
            }

            let file = File::create(&self.save_file)
                .context("Unable to create save file")
                .map_err(|e| Error::new(RetryAdvice::No, e))?;
            serde_json::to_writer(file, token)
                .context("Unable to save new refresh token to file")
                .map_err(|e| Error::new(RetryAdvice::No, e))?;

            Ok(())
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            match fs::remove_file(&self.save_file) {
                Ok(_) => Ok(()),
                Err(e) => match e.kind() {
                    ErrorKind::NotFound => Ok(()),
                    _ => Err(Error::new(RetryAdvice::No, e)),
                },
            }
        })
    }
}
