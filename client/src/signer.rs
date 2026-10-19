use hardware_enclave::{AccessPolicy, EnclaveConfig, SignerHandle, create_signer};
use huskarl::core::crypto::signer::{AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector};
use huskarl::core::jwk::{EcPublicKey, PublicJwk};
use huskarl::core::platform::MaybeSendBoxFuture;
use huskarl::core::{Error, RetryAdvice};
use p256::ecdsa::Signature;
use rootcause::bail;
use rootcause::prelude::ResultExt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

// TODO set at build time
const APP_NAME: &str = "turnkey-rs";
pub(crate) const DEFAULT_KEY_NAME: &str = "DPoP";

const KEY_ALGORITHM: &str = "ES256";

#[derive(Debug, Clone)]
pub struct TpmDPoPSigner {
    key_name: String,
    signer: Arc<SignerHandle>,
    public_jwk: PublicJwk
}

impl TpmDPoPSigner {
    pub fn new(key_name: &str, access: AccessPolicy) -> rootcause::Result<Self> {
        let cfg = EnclaveConfig::new(APP_NAME, "default");
        let signer = create_signer(&cfg).context("Unable to obtain TPM signer handle")?;

        let pk_bytes = if signer.key_exists(key_name).unwrap_or(false) {
            signer.public_key(key_name).context_with(|| format!("Unable to read TPM public key: {key_name}"))?
        } else {
            signer.generate_key(key_name, access).context_with(|| format!("Unable to generate TPM public key: {key_name}"))?
        };

        let public_jwk = sec1_to_jwk(&pk_bytes)?;

        Ok(Self {
            key_name: key_name.into(),
            signer: Arc::new(signer),
            public_jwk
        })
    }
}

impl JwsSigner for TpmDPoPSigner {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(KEY_ALGORITHM)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.public_jwk.kid.clone().map(Cow::Owned)
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            // hardware-enclave returns a DER-encoded ECDSA signature
            let sig_der = self.signer.sign(&self.key_name, input)
                .map_err(|e| Error::new(RetryAdvice::No, e))?;

            der_to_raw(&sig_der)
        })
    }
}

impl AsymmetricJwsSigner for TpmDPoPSigner {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        Cow::Borrowed(&self.public_jwk)
    }
}

#[derive(Debug, Clone)]
pub struct TpmDPoPSelector {
    signers: HashMap<String, Arc<TpmDPoPSigner>>,
    default_signer: Arc<TpmDPoPSigner>,
}

impl TpmDPoPSelector {
    pub fn new(default_signer: TpmDPoPSigner) -> Self {
        let default_signer = Arc::new(default_signer);
        let mut signers = HashMap::new();

        let thumbprint = default_signer.public_jwk.thumbprint();
        signers.insert(thumbprint, default_signer.clone());

        Self {
            signers,
            default_signer,
        }
    }
}

impl JwsSignerSelector for TpmDPoPSelector {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        Box::pin(async move {
            self.default_signer.clone() as Arc<dyn JwsSigner>
        })
    }
}

impl AsymmetricJwsSignerSelector for TpmDPoPSelector {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        Box::pin(async move {
            self.default_signer.clone() as Arc<dyn AsymmetricJwsSigner>
        })
    }

    fn select_signer_by_thumbprint<'a>(&'a self, thumbprint: &'a str) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        Box::pin(async move {
            self.signers.get(thumbprint).cloned().map(|it| it as Arc<dyn AsymmetricJwsSigner>)
        })
    }
}

fn der_to_raw(der: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let sig = Signature::from_der(der)
        .map_err(|e| Error::new(RetryAdvice::No, e))?;

    Ok(sig.to_vec())
}

fn sec1_to_jwk(sec1: &[u8]) -> rootcause::Result<PublicJwk> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        bail!("Invalid SEC1 P-256 public key");
    }

    let x = sec1[1..33].to_vec();
    let y = sec1[33..65].to_vec();

    Ok(PublicJwk::builder()
        .algorithm(KEY_ALGORITHM)
        .key(EcPublicKey::builder()
            .crv("P-256")
            .x(x)
            .y(y)
            .build()
        )
        .build())
}