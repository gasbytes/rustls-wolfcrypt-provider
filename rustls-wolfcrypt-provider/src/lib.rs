#![cfg_attr(not(test), no_std)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
pub mod error;
mod hkdf;
pub mod kx;
mod prf;
mod random;
mod verify;
use crate::hkdf::WCHkdfUsingHmac;
use crate::prf::WCPrfUsingHmac;
pub mod aead {
    pub mod aes128gcm;
    pub mod aes256gcm;
    #[cfg(not(fips))]
    pub mod chacha20;
    #[cfg(feature = "quic")]
    pub mod quic;
}
pub mod sign {
    pub mod ecdsa;
    #[cfg(not(fips_v5))]
    pub mod eddsa;
    pub mod rsa;
}
#[cfg(not(fips))]
use crate::aead::chacha20;
#[cfg(feature = "quic")]
use crate::aead::quic::KeyFactory;
use crate::aead::{aes128gcm, aes256gcm};

pub mod hash {
    pub mod sha256;
    pub mod sha384;
}
use crate::hash::{sha256, sha384};

pub mod hmac;

use crate::hmac::WCShaHmac;

pub mod types;

type SigningKeyResult = Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error>;
type SigningKeyFn = dyn Fn(&PrivateKeyDer<'static>) -> SigningKeyResult;
type SigningAlgorithms = Vec<Box<SigningKeyFn>>;

/*
 * Crypto provider struct that we populate with our own crypto backend (wolfcrypt).
 * */
pub fn default_provider() -> CryptoProvider {
    run_fips_self_tests();
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

pub fn provider_with_specified_ciphers(
    ciphers: Vec<rustls::SupportedCipherSuite>,
) -> CryptoProvider {
    run_fips_self_tests();
    CryptoProvider {
        cipher_suites: ciphers,
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

/// Runs wolfCrypt's FIPS self tests before the provider is used, so threads
/// using an algorithm for the first time at once don't race on its self test.
/// A failure leaves the failed algorithms refused, so it shows up on use.
/// Does nothing in non-FIPS builds.
fn run_fips_self_tests() {
    #[cfg(fips)]
    if let Err(rc) = wolfssl_wolfcrypt::fips::run_all_self_tests() {
        log::error!("wolfCrypt FIPS self tests failed: {}", rc);
    }
}

/// The answer every fips method in this provider gives. In FIPS builds it asks
/// wolfSSL at run time, so a failed self test or integrity check answers false.
pub(crate) fn fips() -> bool {
    #[cfg(fips)]
    {
        use wolfssl_wolfcrypt::sys;
        // NORMAL is the only healthy mode, DEGRADED and FAILED mean a self test
        // or the integrity check failed.
        let mode = unsafe { sys::wolfCrypt_GetMode_fips() };
        mode == sys::FipsModeId_FIPS_MODE_NORMAL as core::ffi::c_int
    }
    #[cfg(not(fips))]
    {
        false
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        match random::wolfcrypt_random_buffer_generator(bytes) {
            Ok(()) => Ok(()),
            Err(_) => Err(rustls::crypto::GetRandomFailed),
        }
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        // Define supported algorithms as closures
        let algorithms: SigningAlgorithms = vec![
            Box::new(|key| sign::ecdsa::EcdsaSigningKey::try_from(key).map(|x| Arc::new(x) as _)),
            Box::new(|key| sign::rsa::RsaPrivateKey::try_from(key).map(|x| Arc::new(x) as _)),
            #[cfg(not(fips_v5))]
            Box::new(|key| sign::eddsa::Ed25519PrivateKey::try_from(key).map(|x| Arc::new(x) as _)),
        ];

        for algorithm in algorithms {
            match algorithm(&key_der) {
                Ok(signing_key) => return Ok(signing_key), // Return the key if the algorithm succeeds
                Err(_) => continue, // Ignore the error and move to the next algorithm
            }
        }

        // If no algorithm succeeded, return an error
        Err(rustls::Error::General(
            "Unsupported private key format".into(),
        ))
    }
}

pub static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    #[cfg(not(fips))]
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(not(fips))]
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(not(fips))]
    TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];

static ALL_RSA_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
];

static ALL_ECDSA_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    #[cfg(not(fips_v5))]
    rustls::SignatureScheme::ED25519,
];

#[cfg(not(fips))]
pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha256),
        aead_alg: &chacha20::Chacha20Poly1305,
        #[cfg(not(feature = "quic"))]
        quic: None,
        #[cfg(feature = "quic")]
        quic: Some(&KeyFactory {
            packet_algo: &aead::quic::CHACHA20_POLY1305,
            header_algo: &aead::quic::CHACHA20,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
            confidentiality_limit: u64::MAX,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
            integrity_limit: 1 << 36,
        }),
    });

pub static TLS13_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha256),
        aead_alg: &aes128gcm::Aes128Gcm,
        #[cfg(not(feature = "quic"))]
        quic: None,
        #[cfg(feature = "quic")]
        quic: Some(&KeyFactory {
            packet_algo: &aead::quic::AES_128_GCM,
            header_algo: &aead::quic::AES_128,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

pub static TLS13_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha384),
        aead_alg: &aes256gcm::Aes256Gcm,
        #[cfg(not(feature = "quic"))]
        quic: None,
        #[cfg(feature = "quic")]
        quic: Some(&KeyFactory {
            packet_algo: &aead::quic::AES_256_GCM,
            header_algo: &aead::quic::AES_256,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

#[cfg(not(fips))]
pub static TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        aead_alg: &chacha20::Chacha20Poly1305,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

pub static TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes128gcm::Aes128Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

pub static TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes256gcm::Aes256Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha384),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

#[cfg(not(fips))]
pub static TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
        aead_alg: &chacha20::Chacha20Poly1305,
    });

pub static TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes128gcm::Aes128Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
    });

pub static TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes256gcm::Aes256Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha384),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
    });

#[cfg(test)]
mod tests {
    // rustls calls the provider FIPS only if every part of it says so,
    // QUIC included when that feature is on.
    #[test]
    fn test_fips_matches_build() {
        assert_eq!(crate::default_provider().fips(), cfg!(fips));
    }
}
