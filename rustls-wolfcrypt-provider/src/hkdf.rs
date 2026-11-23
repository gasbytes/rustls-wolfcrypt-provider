use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::hmac::Hmac as RustlsHmac;
use rustls::crypto::tls13::{self, Hkdf as RustlsHkdf};
use wolfssl_wolfcrypt::hkdf::{hkdf_expand, hkdf_extract};

#[cfg(fips)]
use wolfssl_wolfcrypt::fips::PrivateKeyRead;

use crate::hmac::WCShaHmac;
use zeroize::Zeroizing;

pub struct WCHkdfUsingHmac(pub WCShaHmac);

impl RustlsHkdf for WCHkdfUsingHmac {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_len = self.0.hash_len();
        let ikm = vec![0u8; hash_len];
        self.extract_from_secret(salt, &ikm)
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_len = self.0.hash_len();
        let mut extracted_key = vec![0u8; hash_len];
        let zero_salt = vec![0u8; hash_len];
        let salt_bytes = salt.unwrap_or(&zero_salt);

        #[cfg(fips)]
        let _read = PrivateKeyRead::enable().ok();
        hkdf_extract(
            self.0.hash_type(),
            Some(salt_bytes),
            ikm,
            &mut extracted_key,
        )
        .expect("hkdf_extract failed");

        Box::new(WolfHkdfExpander::new(
            Zeroizing::new(extracted_key),
            self.0.hash_type(),
            self.0.hash_len(),
        ))
    }

    fn expander_for_okm(
        &self,
        okm: &rustls::crypto::tls13::OkmBlock,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        Box::new(WolfHkdfExpander {
            extracted_key: Zeroizing::new(okm.as_ref().to_vec()),
            hash_type: self.0.hash_type(),
            hash_len: self.0.hash_len(),
        })
    }

    fn hmac_sign(
        &self,
        key: &rustls::crypto::tls13::OkmBlock,
        message: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        self.0.with_key(key.as_ref()).sign(&[message])
    }
}

/// Expander implementation that holds the extracted key material from HKDF extract phase
struct WolfHkdfExpander {
    extracted_key: Zeroizing<Vec<u8>>, // The pseudorandom key (PRK) output from HKDF-Extract
    hash_type: i32,                    // The wolfSSL hash algorithm identifier
    hash_len: usize,                   // Length of the hash function output
}

impl WolfHkdfExpander {
    fn new(extracted_key: Zeroizing<Vec<u8>>, hash_type: i32, hash_len: usize) -> Self {
        Self {
            extracted_key,
            hash_type,
            hash_len,
        }
    }
}

impl tls13::HkdfExpander for WolfHkdfExpander {
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), tls13::OutputLengthError> {
        let info_concat = info.concat();

        if output.len() > 255 * self.hash_len {
            return Err(tls13::OutputLengthError);
        }

        #[cfg(fips)]
        let _read = PrivateKeyRead::enable().ok();
        hkdf_expand(
            self.hash_type,
            &self.extracted_key,
            Some(&info_concat),
            output,
        )
        .map_err(|_| tls13::OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> tls13::OkmBlock {
        let mut output = vec![0u8; self.hash_len];
        self.expand_slice(info, &mut output)
            .expect("HKDF-Expand failed during TLS 1.3 key derivation");
        tls13::OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        self.hash_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(fips))]
    use crate::TLS13_CHACHA20_POLY1305_SHA256;
    use crate::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
    use hex_literal::hex;
    use wycheproof::{hkdf::TestName, TestResult};

    /// Tests the HKDF implementation against RFC 5869 test vector A.1
    /// This is the primary compliance test using SHA-256
    /// Its 13 byte salt is under FIPS v5.2.3's 14 byte HMAC key minimum.
    #[test]
    #[cfg(not(fips_v5))]
    fn test_hkdf_sha256() {
        // Test vectors from RFC 5869 Appendix A.1
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        );

        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 42]; // Length from test vector
        expander.expand_slice(&[&info], &mut okm).unwrap();

        assert_eq!(&okm[..], &expected_okm[..]);
    }

    /// Tests HKDF with SHA-384 to ensure it works with different hash functions
    /// Note: This test doesn't verify against RFC test vectors
    #[test]
    fn test_hkdf_sha384() {
        // Test with SHA384
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        // At least 14 bytes, FIPS v5.2.3's HMAC key minimum.
        let salt = hex!("000102030405060708090a0b0c0d0e0f");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha384);
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 48]; // SHA384 output length
        expander.expand_slice(&[&info], &mut okm).unwrap();

        // Just verify we can generate output - actual value would need a verified test vector
        assert!(!okm.iter().all(|&x| x == 0));
    }

    /// Verifies that the HKDF implementation correctly enforces the output length limit
    /// The limit is 255 times the hash length as specified in RFC 5869
    #[test]
    fn test_hkdf_output_length_limit() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        let expander = hkdf.extract_from_zero_ikm(None);

        // Maximum allowed length (255 * hash_len)
        let max_len = 255 * 32;
        let mut okm = vec![0u8; max_len];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_ok());

        // Exceeding maximum length should fail
        let mut okm = vec![0u8; max_len + 1];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_err());
    }

    /// Tests the special case of zero input key material
    /// This is important for TLS 1.3 which sometimes requires derivation from zero IKM
    #[test]
    fn test_hkdf_zero_ikm() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        // At least 14 bytes, FIPS v5.2.3's HMAC key minimum.
        let salt = hex!("000102030405060708090a0b0c0d0e0f");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        let mut okm1 = vec![0u8; 32];
        expander.expand_slice(&[&info], &mut okm1).unwrap();

        // Verify that zero IKM produces consistent output
        let expander2 = hkdf.extract_from_zero_ikm(Some(&salt));
        let mut okm2 = vec![0u8; 32];
        expander2.expand_slice(&[&info], &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    /// Tests that the implementation correctly handles multiple info components
    /// Verifies that passing multiple info slices produces the same result as their concatenation
    #[test]
    fn test_hkdf_multiple_info_components() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::Sha256);
        // At least 14 bytes, FIPS v5.2.3's HMAC key minimum.
        let salt = hex!("000102030405060708090a0b0c0d0e0f");
        let info1 = hex!("f0f1f2f3");
        let info2 = hex!("f4f5f6f7");
        let info3 = hex!("f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        // Test with multiple info components
        let mut okm1 = vec![0u8; 32];
        expander
            .expand_slice(&[&info1, &info2, &info3], &mut okm1)
            .unwrap();

        // Test with concatenated info
        let mut info_concat = Vec::new();
        info_concat.extend_from_slice(&info1);
        info_concat.extend_from_slice(&info2);
        info_concat.extend_from_slice(&info3);

        let mut okm2 = vec![0u8; 32];
        expander.expand_slice(&[&info_concat], &mut okm2).unwrap();

        // Results should be identical
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_wycheproof_sha256() {
        let suites: &[rustls::SupportedCipherSuite] = &[
            TLS13_AES_128_GCM_SHA256,
            #[cfg(not(fips))]
            TLS13_CHACHA20_POLY1305_SHA256,
        ];

        let test_name: TestName = TestName::HkdfSha256;

        let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

        let test_groups = &test_set.test_groups;

        for suite in suites {
            let hkdf_provider = suite.tls13().unwrap().hkdf_provider;

            for test_group in test_groups {
                let tests = &test_group.tests;
                for test in tests {
                    // FIPS v5.2.3 refuses HMAC keys, so HKDF salts, under 14 bytes.
                    if cfg!(fips_v5) && test.salt.len() < 14 {
                        continue;
                    }
                    let pseudorandom_key_expander =
                        hkdf_provider.extract_from_secret(Some(&test.salt), &test.ikm);
                    let mut outputkey_material = vec![0; test.size];
                    let result = pseudorandom_key_expander
                        .expand_slice(&[&test.info], &mut outputkey_material);

                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(result.is_ok());
                            assert_eq!(
                                outputkey_material[..],
                                test.okm[..],
                                "Failed test: {}",
                                test.comment
                            );
                        }
                        TestResult::Invalid => {
                            assert!(result.is_err(), "Failed test: {}", test.comment)
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_hkdf_wycheproof_sha384() {
        let suites: &[rustls::SupportedCipherSuite] = &[TLS13_AES_256_GCM_SHA384];

        let test_name: TestName = TestName::HkdfSha384;

        let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

        let test_groups = &test_set.test_groups;

        for suite in suites {
            let hkdf_provider = suite.tls13().unwrap().hkdf_provider;

            for test_group in test_groups {
                let tests = &test_group.tests;
                for test in tests {
                    // FIPS v5.2.3 refuses HMAC keys, so HKDF salts, under 14 bytes.
                    if cfg!(fips_v5) && test.salt.len() < 14 {
                        continue;
                    }
                    let pseudorandom_key_expander =
                        hkdf_provider.extract_from_secret(Some(&test.salt), &test.ikm);
                    let mut outputkey_material = vec![0; test.size];
                    let result = pseudorandom_key_expander
                        .expand_slice(&[&test.info], &mut outputkey_material);

                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(result.is_ok());
                            assert_eq!(
                                outputkey_material[..],
                                test.okm[..],
                                "Failed test: {}",
                                test.comment
                            );
                        }
                        TestResult::Invalid => {
                            assert!(result.is_err(), "Failed test: {}", test.comment)
                        }
                    }
                }
            }
        }
    }
}
