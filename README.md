# rustls-wolfcrypt-provider

Code that lets you use `wolfCrypt` as a crypto provider for `Rustls`,
built with `no_std` support as its foundation. The `std` library is pulled in
only for testing and during the `build.rs` binding generation; the core crypto
provider itself operates independently of `std`.

## Status

This is in an alpha stage, particularly because the Rustls API is not yet stable.
This code currently works with Rustls 0.23.46 or any later 0.23 release.

## Repo Structure

- **rustls-wolfcrypt-provider**: Crate containing the code that lets you use rustls with wolfcrypt as a crypto provider.

It calls wolfCrypt through the official [`wolfssl-wolfcrypt`](https://github.com/wolfSSL/wolfssl/tree/master/wrapper/rust/wolfssl-wolfcrypt) crate, which links an installed wolfSSL.

## Cipher Suites (Currently) Supported

### TLS 1.3:
- `TLS13_CHACHA20_POLY1305_SHA256`
- `TLS13_AES_128_GCM_SHA256`
- `TLS13_AES_256_GCM_SHA384`

### TLS 1.2:
- `TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

For more details about the supported curves, verification/signing methods, and algorithms, please consult the respective folders.

## Usage

### Initial Setup and Installation
*Rustc 1.85+ is required.*

1. Clone the repository:
   ```
   git clone --depth=1 git@github.com:wolfssl/rustls-wolfcrypt-provider.git
   cd rustls-wolfcrypt-provider/
   ```

2. Build and install wolfSSL as a shared library (from a checkout of
   [wolfSSL](https://github.com/wolfSSL/wolfssl)):
   ```
   ./autogen.sh
   ./configure --prefix=<install dir> --enable-all-crypto --enable-shared \
       --disable-static CPPFLAGS=-DWOLFSSL_RSA_KEY_CHECK
   make
   make install
   ```

3. Build the crate and run the tests. `WOLFSSL_PREFIX` tells the wolfCrypt
   crate where wolfSSL is installed, and the library directory must be on the
   loader path. The end-to-end tests run wolfSSL's example server
   (`WOLFSSL_SERVER`) from the wolfSSL source tree (`WOLFSSL_SRC`):
   ```
   export WOLFSSL_PREFIX=<install dir>
   export LD_LIBRARY_PATH=$WOLFSSL_PREFIX/lib    # DYLD_LIBRARY_PATH on macOS
   export WOLFSSL_SRC=<wolfSSL checkout>
   export WOLFSSL_SERVER=$WOLFSSL_SRC/examples/server/server
   cd rustls-wolfcrypt-provider/
   make build
   make test
   ```

### Example Usage
For `Rustls` usage, consult the `examples` folder in this repository. Each example
demonstrates setting up and using `rustls-wolfcrypt-provider` with specific
cipher suites and configurations.
