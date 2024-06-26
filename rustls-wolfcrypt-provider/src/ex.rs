use wolfcrypt_rs::*;
use std::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub struct Curve25519KeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for Curve25519KeyObjectRef {
    type CType = curve25519_key;
}

pub struct Curve25519KeyObject(NonNull<curve25519_key>);
unsafe impl Sync for Curve25519KeyObject{}
unsafe impl Send for Curve25519KeyObject{}
unsafe impl ForeignType for Curve25519KeyObject {
    type CType = curve25519_key;

    type Ref = Curve25519KeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

pub struct KeyExchange {
    public_key: Curve25519KeyObject,
    private_key: Curve25519KeyObject,
}

impl KeyExchange {
    pub fn use_curve25519() -> Self {
        unsafe {
            let mut public_key: curve25519_key = mem::zeroed();
            let mut private_key: curve25519_key = mem::zeroed();
            let public_key_object = Curve25519KeyObject::from_ptr(&mut public_key);
            let private_key_object = Curve25519KeyObject::from_ptr(&mut private_key);
            let mut ret;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_curve25519_init(public_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }
            ret = wc_curve25519_init(private_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_make_key(&mut rng, 32, public_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }
            ret = wc_curve25519_make_key(&mut rng, 32, public_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve25519_make_key");
            }

            Self {
                public_key: public_key_object,
                private_key: private_key_object
            }
        }
    }

    pub fn derive_shared_secret(&mut self) -> u8 {
        unsafe {
            let ret;
            let mut out: u8 = mem::zeroed();
            let mut out_length: u32 = 32;


            ret = wc_curve25519_shared_secret(self.private_key.as_ptr(), self.public_key.as_ptr(), &mut out, &mut out_length);
            if ret != 0 {
                panic!("failed when calling wc_curve25519_shared_secret with ret value: {}", ret);
            }

            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyExchange};
    use std::boxed::Box;
    
    #[test]
    fn test_curve25519() {
        let mut alice = KeyExchange::use_curve25519();
        let mut bob = KeyExchange::use_curve25519();

        assert_eq!(
            alice.derive_shared_secret(), 
            bob.derive_shared_secret(), 
        );
    }
}
