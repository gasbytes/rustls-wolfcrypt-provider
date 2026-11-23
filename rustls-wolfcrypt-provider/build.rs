// Turns on the `fips` cfg when wolfssl-wolfcrypt is built against a FIPS
// wolfSSL. The crate publishes that as FIPS=1 in its build metadata, which
// Cargo hands to crates depending on it directly as DEP_WOLFSSL_FIPS.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(fips)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_FIPS");
    if std::env::var("DEP_WOLFSSL_FIPS").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=fips");
    }
    // wc_RsaSetRNG only exists in builds with RSA blinding, published as
    // RSA_SETRNG=1.
    println!("cargo::rustc-check-cfg=cfg(rsa_setrng)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_RSA_SETRNG");
    if std::env::var("DEP_WOLFSSL_RSA_SETRNG").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=rsa_setrng");
    }
    // FIPS v5 modules have no Ed25519, published as FIPS_V5=1.
    println!("cargo::rustc-check-cfg=cfg(fips_v5)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_FIPS_V5");
    if std::env::var("DEP_WOLFSSL_FIPS_V5").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=fips_v5");
    }
}
