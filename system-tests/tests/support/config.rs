//! Shared `backend`/`bff` config builders for tests that spin up real
//! servers -- keeps the sane defaults (rate limits generous enough for a
//! test run, cookie name, etc) in one place.

/// Where a successful flow should land the browser. Not a real host -- these
/// tests never actually navigate there (see `super::http::stop_at_real_hosts`),
/// it's only ever checked as a `Location` target.
pub const FINAL_REDIRECT: &str = "http://admin.test/";
/// Where the browser bounces back to on failure. Same deal: never actually
/// fetched, only checked as a `Location` target.
pub const NEXT: &str = "http://login.test/";
pub const NEXT_ORIGIN: &str = "http://login.test";

pub fn backend_config(redirect_uri_allowlist: Vec<String>) -> weaveauth::config::Config {
    weaveauth::config::Config {
        redirect_uri_allowlist,
        ..Default::default()
    }
}

pub fn bff_config(backend_url: String, bff_url: String, trusted_origins: Vec<String>) -> weaveauth_bff::config::Config {
    weaveauth_bff::config::Config {
        bff_url,
        backend_url,
        trusted_origins,
        rate_limit_max_attempts: 1000,
        ..Default::default()
    }
}
