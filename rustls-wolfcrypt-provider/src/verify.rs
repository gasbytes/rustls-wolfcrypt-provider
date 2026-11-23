use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use wolfssl_wolfcrypt::sha::{SHA256, SHA384, SHA512};

mod ecdsa;
#[cfg(not(fips_v5))]
pub mod eddsa;
mod rsapkcs1;
mod rsapss;

/// Hash a message before checking (or making) its signature.
#[derive(Clone, Copy)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// Returns the digest in a buffer big enough for any of the hashes,
    /// along with its length.
    pub(crate) fn digest(
        self,
        message: &[u8],
    ) -> Result<([u8; SHA512::DIGEST_SIZE], usize), InvalidSignature> {
        let mut out = [0u8; SHA512::DIGEST_SIZE];
        let len = match self {
            Hash::Sha256 => {
                let mut sha = SHA256::new().map_err(|_| InvalidSignature)?;
                sha.update(message).map_err(|_| InvalidSignature)?;
                sha.finalize(&mut out[..SHA256::DIGEST_SIZE])
                    .map_err(|_| InvalidSignature)?;
                SHA256::DIGEST_SIZE
            }
            Hash::Sha384 => {
                let mut sha = SHA384::new().map_err(|_| InvalidSignature)?;
                sha.update(message).map_err(|_| InvalidSignature)?;
                sha.finalize(&mut out[..SHA384::DIGEST_SIZE])
                    .map_err(|_| InvalidSignature)?;
                SHA384::DIGEST_SIZE
            }
            Hash::Sha512 => {
                let mut sha = SHA512::new().map_err(|_| InvalidSignature)?;
                sha.update(message).map_err(|_| InvalidSignature)?;
                sha.finalize(&mut out).map_err(|_| InvalidSignature)?;
                SHA512::DIGEST_SIZE
            }
        };
        Ok((out, len))
    }
}

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA512,
        #[cfg(not(fips_v5))]
        ED25519,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384]),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        #[cfg(not(fips_v5))]
        (SignatureScheme::ED25519, &[ED25519]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha256Verify;
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha384Verify;
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha512Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha256Verify;
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha384Verify;
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha512Verify;
static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P256_SHA256;
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P384_SHA384;
static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P521_SHA512;
#[cfg(not(fips_v5))]
static ED25519: &dyn SignatureVerificationAlgorithm = &eddsa::Ed25519;
