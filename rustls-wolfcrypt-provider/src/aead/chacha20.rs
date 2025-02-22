use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::KeySizeUser;
use core::mem;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use wolfcrypt_rs::*;

use crate::error::check_if_zero;

const CHACHAPOLY1305_OVERHEAD: usize = 16;

pub struct Chacha20Poly1305;

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut key_as_vec = vec![0u8; 32];
        key_as_vec.copy_from_slice(key.as_ref());

        Box::new(WCTls12Cipher {
            key: key_as_vec,
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut key_as_vec = vec![0u8; 32];
        key_as_vec.copy_from_slice(key.as_ref());

        Box::new(WCTls12Cipher {
            key: key_as_vec,
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

pub struct WCTls12Cipher {
    key: Vec<u8>,
    iv: Iv,
}

impl MessageEncrypter for WCTls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        // We load the payload into the PrefixedPayload struct,
        // required by OutboundOpaqueMessage.
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks.
        payload.extend_from_chunks(&m.payload);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let mut encrypted = vec![0u8; m.payload.len()];
        let mut auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] =
            unsafe { mem::zeroed() };
        let payload_raw = payload.as_ref();

        //  This function encrypts an input message, inPlaintext,
        //  using the ChaCha20 stream cipher, into the output buffer, outCiphertext.
        //  It also performs Poly-1305 authentication (on the cipher text),
        //  and stores the generated authentication tag in the output buffer, outAuthTag.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                payload_raw.as_ptr(),
                m.payload.len() as word32,
                encrypted.as_mut_ptr(),
                auth_tag.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let mut output = PrefixedPayload::with_capacity(total_len);

        // Finally we copy the encrypted payload into a PrefixedPayload
        // struct, extending it from a slice (encrypted is a Vec<u8>)...
        output.extend_from_slice(encrypted.as_slice());

        // ...and add at the end of it the authentication tag.
        output.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, output))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;

        // We substract the tag, so this len will only consider
        // the message that we are trying to decrypt.
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, message_len);
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        auth_tag.copy_from_slice(&payload[message_len..]);

        // This function decrypts input ciphertext, inCiphertext,
        // using the ChaCha20 stream cipher, into the output buffer, outPlaintext.
        // It also performs Poly-1305 authentication, comparing the given inAuthTag
        // to an authentication generated with the inAAD (arbitrary length additional authentication data).
        // Note: If the generated authentication tag does not match the supplied
        // authentication tag, the text is not decrypted.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                self.key.as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                payload[..message_len].as_ptr(), // we decrypt only the payload, we don't include the tag.
                message_len as word32,
                auth_tag.as_ptr(),
                payload[..message_len].as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        // We extract the final result...
        payload.truncate(message_len);

        Ok(
            // ...And convert it into the
            // InboundPlainMessage type.
            m.into_plain_message(),
        )
    }
}

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let mut key_as_array = [0u8; 32];
        key_as_array[..32].copy_from_slice(key.as_ref());

        Box::new(WCTls13Cipher {
            key: key_as_array,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let mut key_as_array = [0u8; 32];
        key_as_array[..32].copy_from_slice(key.as_ref());

        Box::new(WCTls13Cipher {
            key: key_as_array,
            iv,
        })
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

pub struct WCTls13Cipher {
    key: [u8; 32],
    iv: Iv,
}

impl MessageEncrypter for WCTls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks, followed by
        // an extend_from_slice to add the ContentType at the end of it.
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);
        let mut auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] =
            unsafe { mem::zeroed() };

        // This function encrypts an input message, inPlaintext,
        // using the ChaCha20 stream cipher, into the output buffer, outCiphertext.
        // It also performs Poly-1305 authentication (on the cipher text),
        // and stores the generated authentication tag in the output buffer, outAuthTag.
        // We need to also need to include for the encoding type, apparently, hence the + 1
        // otherwise the rustls returns EoF.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                payload.as_ref()[..m.payload.len() + 1].as_ptr(),
                (m.payload.len() + 1) as word32,
                payload.as_mut()[..m.payload.len() + 1].as_mut_ptr(),
                auth_tag.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        // Finally, we add the authentication tag at the end of it
        // after the process of encryption is done.
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        auth_tag.copy_from_slice(&payload[message_len..]);

        // This function decrypts input ciphertext, inCiphertext,
        // using the ChaCha20 stream cipher, into the output buffer, outPlaintext.
        // It also performs Poly-1305 authentication, comparing the given inAuthTag
        // to an authentication generated with the inAAD (arbitrary length additional authentication data).
        // Note: If the generated authentication tag does not match the supplied
        // authentication tag, the text is not decrypted.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                self.key.as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                // [..message_len] since we want to exclude the
                // the auth_tag.
                payload[..message_len].as_ptr(),
                message_len as word32,
                auth_tag.as_ptr(),
                payload[..message_len].as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        // We extract the final result...
        payload.truncate(message_len);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::{aead::TestFlag, TestResult};

    #[test]
    fn test_chacha() {
        let mut key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let mut plain_text: [u8; 114] = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let mut iv: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let mut aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let mut cipher: [u8; 114] = [
            /* expected output from operation */
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let mut auth_tag: [u8; 16] = [
            /* expected output from operation */
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        let mut generated_plain_text: [u8; 114] = unsafe { mem::zeroed() };
        let mut generated_cipher_text: [u8; 114] = unsafe { mem::zeroed() };
        let mut generated_auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] =
            unsafe { mem::zeroed() };
        let mut ret;

        ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                key.as_mut_ptr(),
                iv.as_mut_ptr(),
                aad.as_mut_ptr(),
                aad.len() as word32,
                plain_text.as_mut_ptr(),
                plain_text.len() as word32,
                generated_cipher_text.as_mut_ptr(),
                generated_auth_tag.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        assert_eq!(generated_cipher_text, cipher);
        assert_eq!(generated_auth_tag, auth_tag);

        ret = unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                key.as_mut_ptr(),
                iv.as_mut_ptr(),
                aad.as_mut_ptr(),
                aad.len() as word32,
                cipher.as_mut_ptr(),
                cipher.len() as word32,
                auth_tag.as_mut_ptr(),
                generated_plain_text.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        assert_eq!(generated_plain_text, plain_text);
    }

    #[test]
    fn test_chacha20poly1305_wycheproof() {
        let test_name = wycheproof::aead::TestName::ChaCha20Poly1305;
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();
        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 256)
            .filter(|group| group.nonce_size == 96)
        {
            for test in group.tests {
                counter += 1;

                let mut actual_ciphertext = test.pt.to_vec();
                let mut actual_tag = [0u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize];

                let encrypt_result = unsafe {
                    wc_ChaCha20Poly1305_Encrypt(
                        test.key.as_ptr(),
                        test.nonce.as_ptr(),
                        test.aad.as_ptr(),
                        test.aad.len() as word32,
                        test.pt.as_ptr(),
                        test.pt.len() as word32,
                        actual_ciphertext.as_mut_ptr(),
                        actual_tag.as_mut_ptr(),
                    )
                };

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.iter().any(|flag| *flag == TestFlag::ModifiedTag) {
                            assert_ne!(
                                actual_tag[..],
                                test.tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id,
                                test.comment
                            );
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(
                            encrypt_result, 0,
                            "Encryption failed for test case {}: {}",
                            test.tc_id, test.comment
                        );

                        assert_eq!(
                            actual_ciphertext[..],
                            test.ct[..],
                            "Encryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );

                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Tag mismatch in test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }

                let mut decrypted_data = test.ct.to_vec();
                let decrypt_result = unsafe {
                    wc_ChaCha20Poly1305_Decrypt(
                        test.key.as_ptr(),
                        test.nonce.as_ptr(),
                        test.aad.as_ptr(),
                        test.aad.len() as word32,
                        test.ct.as_ptr(),
                        test.ct.len() as word32,
                        test.tag.as_ptr(),
                        decrypted_data.as_mut_ptr(),
                    )
                };

                match &test.result {
                    TestResult::Invalid => {
                        assert!(
                            decrypt_result != 0,
                            "Decryption should have failed for invalid test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(
                            decrypt_result, 0,
                            "Decryption failed for test case {}: {}",
                            test.tc_id, test.comment
                        );
                        assert_eq!(
                            decrypted_data[..],
                            test.pt[..],
                            "Decryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }
            }
        }

        assert!(
            counter > 50,
            "Insufficient number of tests run: {}",
            counter
        );

        log::info!("Counter: {}", counter);
    }
}
