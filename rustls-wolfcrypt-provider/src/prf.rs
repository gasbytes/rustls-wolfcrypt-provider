use rustls::crypto;
use std::boxed::Box;
use wolfcrypt_rs::*;
use std::mem;

pub struct PrfTls12;

impl crypto::tls12::Prf for PrfTls12 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;

        Ok(prf(output, secret.secret_bytes(), label, seed)?)
    }

    fn for_secret(
       &self, 
       output: &mut [u8], 
       secret: &[u8], 
       label: &[u8], 
       seed: &[u8]) -> () {
        prf(output, secret, label, seed).expect("failed to calculate prf in for_secret")
    }
}

fn prf(
   output: &mut [u8],
   secret: &[u8],
   label: &[u8],
   seed: &[u8],
) -> Result<(), rustls::Error> {
    unsafe {
        let ret;
        let use_at_least_sha_256: std::os::raw::c_int = 1;
        
        ret = wc_PRF_TLS(
            output.as_mut_ptr(),
            output.len() as word32,
            secret.as_ptr(),
            secret.len() as word32,
            label.as_ptr(),
            label.len() as word32,
            seed.as_ptr(),
            seed.len() as word32,
            use_at_least_sha_256,
            wc_MACAlgorithm_sha256_mac.try_into().unwrap(),
            std::ptr::null_mut(),
            INVALID_DEVID
        );
        if ret != 0 {
            panic!("failed while calling wc_PRF_TLS, ret value: {}", ret);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_prf() {
        unsafe {
            let pre_master_secret = "D06F9C19BFF49B1E91E4EFE97345D0894E6C2E6C34A165B24540E2970875D6412AA6515871B389B4C199BB8389C71CED".as_bytes();
            let hello_random     = "162B81EDFBEAE4F25240320B87E7651C865564191DD782DB0B9ECA275FBA1BB95A1DA3DF436D68DA86C5E7B4B4A36E46B977C61767983A31BE270D74517BD0F6".as_bytes();
            let master_secret    = "EB38B8D89B98B1C266DE44BB3CA14E83C32F009F9955B1D994E61D3C51EE876090B4EF89CC7AF42F46E72201BFCC7977".as_bytes();
            let label = "master secret".as_bytes();

            let mut pms: [u8; 48] = mem::zeroed();
            let mut seed: [u8; 64] = mem::zeroed();
            let mut ms: [u8; 48] = mem::zeroed();
            let mut result: [u8; 48] = mem::zeroed();

            let pre_master_secret_len: word32 = pre_master_secret.len() as word32;
            let mut pms_sz: word32 = pms.len() as word32;
            let mut seed_sz: word32 = seed.len() as word32;
            let mut ms_sz: word32 = ms.len() as word32;
            let mut ret;

            ret = Base16_Decode(
                pre_master_secret.as_ptr(),
                pre_master_secret_len, 
                pms.as_mut_ptr(), 
                &mut pms_sz as *mut u32);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = Base16_Decode(
                hello_random.as_ptr(),
                hello_random.len() as word32, 
                seed.as_mut_ptr(), 
                &mut seed_sz as *mut u32);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = Base16_Decode(
                master_secret.as_ptr(),
                master_secret.len() as word32, 
                ms.as_mut_ptr(), 
                &mut ms_sz as *mut u32);
            if ret != 0 {
                panic!("failed while calling Base16_Decode, with ret value: {}", ret);
            }

            ret = wc_PRF_TLS(
                result.as_mut_ptr(), 
                ms_sz, 
                pms.as_ptr(), 
                pms_sz,
                label.as_ptr(), 
                label.len() as word32, 
                seed.as_ptr(), 
                seed_sz,
                1, 
                wc_MACAlgorithm_sha256_mac.try_into().unwrap(),
                std::ptr::null_mut(), 
                INVALID_DEVID);
            if ret != 0 {
                panic!("failed while calling wc_PRF_TLS, with ret value: {}", ret);
            }

            assert_eq!(result, ms);
        }
    }
}
