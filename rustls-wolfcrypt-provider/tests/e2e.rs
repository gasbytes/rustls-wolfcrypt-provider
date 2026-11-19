use foreign_types::ForeignType;
use lazy_static::lazy_static;
use rayon::prelude::*;
use rustls::version::{TLS12, TLS13};
use rustls::SignatureScheme;
use rustls_wolfcrypt_provider::error::*;
use rustls_wolfcrypt_provider::types::*;
use rustls_wolfcrypt_provider::{
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
};
#[cfg(not(fips))]
use rustls_wolfcrypt_provider::{
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS13_CHACHA20_POLY1305_SHA256,
};
use std::env;
use std::fs::File;
use std::io::stdout;
use std::io::BufReader;
use std::io::{Read, Write};
use std::mem;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::Once;
use std::sync::{Arc, Mutex};
use std::thread;
use wolfssl_wolfcrypt::ecc::ECC;
#[cfg(not(fips_v5))]
use wolfssl_wolfcrypt::ed25519::Ed25519;
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::sys::*;

/*
 * Version config used by the server to specify
 * the tls version that we wanna use.
 * */
const TLSV1_2: &str = "-v 3";
const TLSV1_3: &str = "-v 4";

/*
 * Global mutex to ensure only one test can access the server at a time.
 * This is needed because both TLS 1.2 and TLS 1.3 tests spin up a local server
 * on the same port (4443). Without synchronization, tests running in parallel
 * could try to bind to the same port or interact with the wrong server instance.
*/
lazy_static! {
    static ref SERVER_LOCK: Mutex<()> = Mutex::new(());
}

/*
 * Initiliaze the thread pool once for all tests.
 * */
static INIT: Once = Once::new();

fn init_thread_pool() {
    INIT.call_once(|| {
        let num_cpus = num_cpus::get();
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus)
            .build_global()
            .unwrap();
    });
}

/*
 * Starts background job for wolfssl server (localhost:4443).
 * WOLFSSL_SERVER is the path to wolfSSL's examples/server/server, and
 * WOLFSSL_SRC the wolfSSL source tree, which the server loads its default
 * certificates from.
 * */
fn start_wolfssl_server(current_dir_string: String, tls_version: &str) -> Child {
    let server = env::var("WOLFSSL_SERVER")
        .expect("WOLFSSL_SERVER must be set to wolfSSL's examples/server/server");
    let wolfssl_src = env::var("WOLFSSL_SRC").expect("WOLFSSL_SRC must be set");

    Command::new(server)
        .current_dir(wolfssl_src)
        .arg("-d")
        .arg("-c")
        .arg(current_dir_string.clone() + "/tests/certs/localhost.pem")
        .arg("-k")
        .arg(current_dir_string.clone() + "/tests/certs/localhost.key")
        .arg("-p")
        .arg("4443")
        .arg(tls_version)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start wolfssl server.")
}

#[cfg(test)]
mod tests {
    use rustls::crypto::CryptoProvider;
    use rustls_pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    use super::*;

    #[test]
    fn test_tls12_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            #[cfg(not(fips))]
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_2,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tls13_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            #[cfg(not(fips))]
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_3,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tl12_against_website() {
        let ciphers = [
            #[cfg(not(fips))]
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    #[test]
    fn test_tl13_against_website() {
        let ciphers = [
            #[cfg(not(fips))]
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite(),
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    /// DER-encodes an ECC private key. The crate has no wrapper for
    /// `wc_EccPrivateKeyToDer`, so this uses the raw bindings.
    fn ecc_private_key_to_der(priv_key: &[u8], pub_key_x963: &[u8], curve_id: i32) -> Vec<u8> {
        let mut der = vec![0u8; 200]; // Adjust size if needed
        unsafe {
            let mut key: ecc_key = mem::zeroed();
            check_if_zero(wc_ecc_init(&mut key)).unwrap();
            let ret = wc_ecc_import_private_key_ex(
                priv_key.as_ptr(),
                priv_key.len() as word32,
                pub_key_x963.as_ptr(),
                pub_key_x963.len() as word32,
                &mut key,
                curve_id,
            );
            let der_len = if ret == 0 {
                wc_EccPrivateKeyToDer(&mut key, der.as_mut_ptr(), der.len() as word32)
            } else {
                ret
            };
            wc_ecc_free(&mut key);
            check_if_greater_than_zero(der_len).unwrap();
            der.truncate(der_len as usize);
        }
        der
    }

    /// DER-encodes an Ed25519 private key. The crate has no wrapper for
    /// `wc_Ed25519PrivateKeyToDer`, so this uses the raw bindings.
    #[cfg(not(fips_v5))]
    fn ed25519_private_key_to_der(priv_key: &[u8], pub_key: &[u8]) -> Vec<u8> {
        let mut der = vec![0u8; 200]; // Adjust size if needed
        unsafe {
            let mut key: ed25519_key = mem::zeroed();
            check_if_zero(wc_ed25519_init(&mut key)).unwrap();
            let ret = wc_ed25519_import_private_key(
                priv_key.as_ptr(),
                priv_key.len() as word32,
                pub_key.as_ptr(),
                pub_key.len() as word32,
                &mut key,
            );
            let der_len = if ret == 0 {
                wc_Ed25519PrivateKeyToDer(&key, der.as_mut_ptr(), der.len() as word32)
            } else {
                ret
            };
            wc_ed25519_free(&mut key);
            check_if_greater_than_zero(der_len).unwrap();
            der.truncate(der_len as usize);
        }
        der
    }

    #[test]
    fn ecdsa_sign_and_verify() {
        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::default_provider();

        // Define schemes, curve IDs, and key sizes as tuples
        let test_configs = [
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                ECC::SECP256R1,
                32, // P256 key size
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                ECC::SECP384R1,
                48, // P384 key size
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                ECC::SECP521R1,
                66, // P521 key size
            ),
        ];

        for &(scheme, curve_id, key_size) in &test_configs {
            // Generate ECC key
            let rng = RNG::new().unwrap();
            let mut key = ECC::generate_ex(key_size as i32, &rng, curve_id, None, None).unwrap();

            // FIPS v5.2.3 locks the public key export too, not only the
            // private one.
            #[cfg(fips)]
            let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().unwrap();

            // Export public key (0x04 || X || Y)
            let mut pub_key_bytes = vec![0u8; 1 + 2 * key_size];
            let pub_len = key.export_x963(&mut pub_key_bytes).unwrap();
            pub_key_bytes.truncate(pub_len);

            // Export private key in DER format
            let mut priv_key_raw = vec![0u8; key_size];
            key.export_private(&mut priv_key_raw).unwrap();
            let der_ecc_key = ecc_private_key_to_der(&priv_key_raw, &pub_key_bytes, curve_id);

            // Convert to PKCS#8 format and verify
            let rustls_private_key_pkcs8 =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der_ecc_key.as_slice()));

            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_pkcs8.clone_key(),
                pub_key_bytes.as_slice(),
            );

            // Convert to SEC1 format and verify
            let rustls_private_key_sec1 =
                PrivateKeyDer::from(PrivateSec1KeyDer::from(der_ecc_key.as_slice()));

            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_sec1.clone_key(),
                pub_key_bytes.as_slice(),
            );
        }
    }

    #[test]
    #[cfg(not(fips_v5))]
    fn eddsa_sign_and_verify() {
        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::default_provider();

        // Generate Ed25519 key
        let rng = RNG::new().unwrap();
        let key = Ed25519::generate(&rng).unwrap();

        // Export private key
        let mut priv_key_raw = [0u8; Ed25519::KEY_SIZE];
        #[cfg(fips)]
        let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().unwrap();
        key.export_private_only(&mut priv_key_raw).unwrap();

        // Export public key
        let mut pub_key_raw = [0u8; Ed25519::PUB_KEY_SIZE];
        key.export_public(&mut pub_key_raw).unwrap();

        // Export private key in DER format
        let der_ed25519_key = ed25519_private_key_to_der(&priv_key_raw, &pub_key_raw);
        let rustls_pkcs8_der = PrivatePkcs8KeyDer::from(der_ed25519_key.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs8_der);

        sign_and_verify(
            &wolfcrypt_default_provider,
            SignatureScheme::ED25519,
            rustls_private_key.clone_key(),
            pub_key_raw.as_slice(),
        );
    }

    #[test]
    fn rsa_pss_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::default_provider();
        let schemes = [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];

        let test_cases: Vec<_> = schemes
            .iter()
            .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
            .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs8_key(&wolfcrypt_default_provider, scheme, key_size)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed for scheme {:?} with key size {}, {:?}",
                        scheme, key_size, e
                    )
                });
        });

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs1_key(&wolfcrypt_default_provider, scheme, key_size)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed for scheme {:?} with key size {}, {:?}",
                        scheme, key_size, e
                    )
                });
        });
    }

    fn generate_and_test_rsa_pkcs8_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut priv_key_der: Vec<u8> = vec![0; 2392];
        let mut pub_key_der: Vec<u8> = vec![0; 2392];

        let ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng_c_type);
        rng_object.init().unwrap();

        // wc_RsaSetRNG only exists in builds with RSA blinding.
        #[cfg(rsa_setrng)]
        unsafe {
            wc_RsaSetRNG(rsa_key_object.as_ptr(), rng_object.as_ptr())
        };

        let ret = unsafe {
            wc_MakeRsaKey(
                rsa_key_object.as_ptr(),
                key_size as i32,
                WC_RSA_EXPONENT.into(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let ret = unsafe {
            wc_RsaKeyToDer(
                rsa_key_object.as_ptr(),
                priv_key_der.as_mut_ptr(),
                priv_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        priv_key_der.resize(ret as usize, 0);

        let rustls_pkcs8_der = PrivatePkcs8KeyDer::from(priv_key_der.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs8_der);

        let ret = unsafe {
            wc_RsaKeyToPublicDer(
                rsa_key_object.as_ptr(),
                pub_key_der.as_mut_ptr(),
                pub_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        pub_key_der.resize(ret as usize, 0);

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            pub_key_der.as_slice(),
        );

        Ok(())
    }

    #[test]
    fn rsa_pkcs1_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::default_provider();
        let test_cases: Vec<_> = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
        .iter()
        .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
        .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs1_key(&wolfcrypt_default_provider, scheme, key_size)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed for scheme {:?} with key size {}, {:?}",
                        scheme, key_size, e
                    )
                });
        });

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_rsa_pkcs8_key(&wolfcrypt_default_provider, scheme, key_size)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed for scheme {:?} with key size {}, {:?}",
                        scheme, key_size, e
                    )
                });
        });
    }

    #[test]
    fn rsa_key_under_2048_bits_refused() {
        let provider = rustls_wolfcrypt_provider::default_provider();
        let der = include_bytes!("certs/rsa1024.der");
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(&der[..]));

        assert!(provider.key_provider.load_private_key(key).is_err());
    }

    fn generate_and_test_rsa_pkcs1_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut priv_key_der: Vec<u8> = vec![0; 2392];
        let mut pub_key_der: Vec<u8> = vec![0; 2392];

        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng_c_type);
        rng_object.init().unwrap();

        // wc_RsaSetRNG only exists in builds with RSA blinding.
        #[cfg(rsa_setrng)]
        unsafe {
            wc_RsaSetRNG(rsa_key_object.as_ptr(), rng_object.as_ptr())
        };

        ret = unsafe {
            wc_MakeRsaKey(
                rsa_key_object.as_ptr(),
                key_size as i32,
                WC_RSA_EXPONENT.into(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_RsaKeyToDer(
                rsa_key_object.as_ptr(),
                priv_key_der.as_mut_ptr(),
                priv_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        priv_key_der.resize(ret as usize, 0);

        let rustls_pkcs1_der = PrivatePkcs1KeyDer::from(priv_key_der.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs1_der);

        ret = unsafe {
            wc_RsaKeyToPublicDer(
                rsa_key_object.as_ptr(),
                pub_key_der.as_mut_ptr(),
                pub_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        pub_key_der.resize(ret as usize, 0);

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            &pub_key_der,
        );
        Ok(())
    }

    fn sign_and_verify(
        provider: &rustls::crypto::CryptoProvider,
        scheme: SignatureScheme,
        rustls_private_key: PrivateKeyDer<'static>,
        pub_key: &[u8],
    ) {
        let data = "data to sign and verify".as_bytes();

        // Signing...
        let signing_key = provider
            .key_provider
            .load_private_key(rustls_private_key)
            .unwrap();

        let signer = signing_key
            .choose_scheme(&[scheme])
            .expect("signing provider supports this scheme");
        let signature = signer.sign(data).unwrap();

        // Verifying...
        let algs = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(k, _v)| *k == scheme)
            .map(|(_k, v)| *v)
            .expect("verifying provider supports this scheme");
        assert!(!algs.is_empty());
        assert!(algs
            .iter()
            .any(|alg| { alg.verify_signature(pub_key, data, &signature).is_ok() }));
    }
}
