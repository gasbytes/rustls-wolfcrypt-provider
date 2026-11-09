#![cfg_attr(read_buf, feature(read_buf))]
#![cfg_attr(read_buf, feature(core_io))]
#![cfg_attr(read_buf, feature(core_io_borrowed_buf))]

use std::cell::RefCell;
use std::env;
use std::sync::Mutex;

#[macro_use]
mod macros;

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_api {
    use super::*;

    provider_wolfcrypt!();

    #[path = "../api.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_client_cert_verifier {

    provider_wolfcrypt!();

    #[path = "../client_cert_verifier.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_key_log_file_env {
    use super::serialized;

    provider_wolfcrypt!();

    #[path = "../key_log_file_env.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_server_cert_verifier {

    provider_wolfcrypt!();

    #[path = "../server_cert_verifier.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_unbuffered {

    provider_wolfcrypt!();

    #[path = "../unbuffered.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_ech {

    provider_wolfcrypt!();

    #[path = "../ech.rs"]
    mod tests;
}

#[cfg(feature = "wolfcrypt-provider")]
#[path = "."]
mod tests_with_wolfcrypt_ffdhe {
    provider_wolfcrypt!();

    #[path = "../api_ffdhe.rs"]
    mod tests;
}

// this must be outside tests_with_*, as we want
// one thread_local!, not one per provider.
thread_local!(static COUNTS: RefCell<LogCounts> = RefCell::new(LogCounts::new()));

struct CountingLogger;

#[allow(dead_code)]
static LOGGER: CountingLogger = CountingLogger;

#[allow(dead_code)]
impl CountingLogger {
    fn install() {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Trace);
    }

    fn reset() {
        COUNTS.with(|c| {
            c.borrow_mut().reset();
        });
    }
}

impl log::Log for CountingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("logging at {:?}: {:?}", record.level(), record.args());

        COUNTS.with(|c| {
            c.borrow_mut()
                .add(record.level(), format!("{}", record.args()));
        });
    }

    fn flush(&self) {}
}

#[derive(Default, Debug)]
struct LogCounts {
    trace: Vec<String>,
    debug: Vec<String>,
    info: Vec<String>,
    warn: Vec<String>,
    error: Vec<String>,
}

impl LogCounts {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn add(&mut self, level: log::Level, message: String) {
        match level {
            log::Level::Trace => &mut self.trace,
            log::Level::Debug => &mut self.debug,
            log::Level::Info => &mut self.info,
            log::Level::Warn => &mut self.warn,
            log::Level::Error => &mut self.error,
        }
        .push(message);
    }
}

/// Approximates `#[serial]` from the `serial_test` crate.
///
/// No attempt is made to recover from a poisoned mutex, which will
/// happen when `f` panics. In other words, all the tests that use
/// `serialized` will start failing after one test panics.
#[allow(dead_code)]
fn serialized(f: impl FnOnce()) {
    // Ensure every test is run serialized
    static MUTEX: Mutex<()> = const { Mutex::new(()) };

    let _guard = MUTEX.lock().unwrap();

    // XXX: NOT thread safe.
    unsafe { env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt") };

    f()
}
