use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::ptr::NonNull;
use std::mem;

#[derive(Clone, Debug)]
pub struct EcdsaSigningKeyP256 {
    key: Arc<ECCKeyObject>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKeyP256 {
    pub fn get_key(&self) -> Arc<ECCKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<PrivateKeyDer<'_>> for EcdsaSigningKeyP256 {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                unsafe {
                    let mut ecc_key_struct: ecc_key = mem::zeroed();
                    let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_key_struct);
                    let pkcs8: &[u8] = der.secret_pkcs8_der();
                    let pkcs8_sz: word32 = pkcs8.len() as word32;
                    let mut ret;

                    // This function initializes an ecc_key object for 
                    // future use with message verification.
                    ret = wc_ecc_init(ecc_key_object.as_ptr());
                    if ret != 0 {
                        panic!("error while calling wc_ecc_init, ret: {}", ret);
                    }

                    let mut idx: u32 = 0; 

                    // This function finds the beginning of the traditional
                    // private key inside a PKCS#8 unencrypted buffer.
                    ret = wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz);
                    if ret < 0 {
                        panic!("error while calling wc_GetPkcs8TraditionalOffset, ret: {}", ret);
                    }

                    // This function reads in an ECC private key from the input buffer, input, 
                    // parses the private key, and uses it to generate an ecc_key object, 
                    // which it stores in key.
                    ret = wc_EccPrivateKeyDecode(
                            pkcs8.as_ptr() as *mut u8, 
                            &mut idx, 
                            ecc_key_object.as_ptr(), 
                            pkcs8_sz
                    );
                    if ret != 0 {
                        panic!("error while calling wc_EccPrivateKeyDecode, ret: {}", ret);
                    }

                   Ok(Self {
                     key: Arc::new(ecc_key_object),
                     scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                   })
                }
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for EcdsaSigningKeyP256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKeyP256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        unsafe {
            let mut ret;
            let mut rng: WC_RNG = mem::zeroed();
            let mut digest: [u8; 32] = [0; 32];
            let message_length: word32 = message.len() as word32;
            let digest_length: word32 = digest.len() as word32;
            let mut sig: [u8; 265] = [0; 265];
            let mut sig_sz: word32 = sig.len() as word32;
            let ecc_key_arc = self.get_key();
            let ecc_key_object = ecc_key_arc.as_ref();

            // We hash the message, since it's not, using Sha256 (ECDSA_NISTP256_SHA256)
            ret = wc_Sha256Hash(message.as_ptr(), message_length, digest.as_mut_ptr());
            if ret != 0 {
                panic!("failed because of wc_Sha256Hash, ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed because of wc_InitRng, ret value: {}", ret);
            }

            // This function signs a message digest 
            // using an ecc_key object to guarantee authenticity.
            ret = wc_ecc_sign_hash(
                digest.as_mut_ptr(), 
                digest_length, 
                sig.as_mut_ptr(), 
                &mut sig_sz, 
                &mut rng, 
                ecc_key_object.as_ptr()
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_sign_hash");
            }

            let sig_vec = sig.to_vec();

            Ok(sig_vec)
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer() { 
        unsafe {
            let message = "message to verify".as_bytes();
            let message_length: word32 = message.len() as word32;
            let mut digest: [u8; 32] = [0; 32];
            let digest_length: word32 = digest.len() as word32;
            let mut ecc_key_struct: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_key_struct);
            let mut rng: WC_RNG = mem::zeroed();
            let mut sig: [u8; 265] = [0; 265];
            let mut sig_sz: word32 = sig.len() as word32;
            let mut ret;

            ret = wc_Sha256Hash(message.as_ptr(), message_length, digest.as_mut_ptr());
            if ret != 0 {
                panic!("failed because of wc_Sha256Hash, ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed because of wc_InitRng, ret value: {}", ret);
            }

            ret = wc_ecc_init(ecc_key_object.as_ptr());
            if ret != 0 {
                panic!("error while calling wc_ecc_init");
            }

            ret = wc_ecc_make_key(&mut rng, 32, ecc_key_object.as_ptr());
            if ret != 0 {
                panic!("error while calling wc_ecc_init");
            }

            ret = wc_ecc_sign_hash(
                    digest.as_mut_ptr(), 
                    digest_length, 
                    sig.as_mut_ptr(), 
                    &mut sig_sz, 
                    &mut rng, 
                    ecc_key_object.as_ptr()
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_sign_hash");
            }

            let mut is_valid_sig: i32 = 0;
            ret = wc_ecc_verify_hash(
                  sig.as_mut_ptr(), 
                  sig_sz, 
                  digest.as_mut_ptr(), 
                  digest_length,
                  &mut is_valid_sig, 
                  ecc_key_object.as_ptr()
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash");
            }

            wc_FreeRng(&mut rng);

            assert_eq!(1, is_valid_sig);
        }
    }
}

pub struct ECCKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for ECCKeyObjectRef {
    type CType = ecc_key;
}

#[derive(Debug, Clone, Copy)]
pub struct ECCKeyObject(NonNull<ecc_key>);
unsafe impl Sync for ECCKeyObject{}
unsafe impl Send for ECCKeyObject{}
unsafe impl ForeignType for ECCKeyObject {
    type CType = ecc_key;

    type Ref = ECCKeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

