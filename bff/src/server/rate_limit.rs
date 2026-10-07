use crate::config::{Config, RATE_LIMIT_WINDOW_SECS};
use common::rate_limit::{Governor, build_governor};

/// Rate-limit buckets, one per client in each (see `common::rate_limit::ClientIpKeyExtractor`).
/// Each allows a burst of its `max_attempts` (`rate_limit_proxy_max_attempts`
/// for `proxy`, `rate_limit_max_attempts` for `auth`), then replenishes one
/// attempt every `RATE_LIMIT_WINDOW_SECS / max_attempts` seconds, to the
/// millisecond and no faster than every 1ms (so above 60000 attempts it
/// refills like 60000).
#[derive(Clone)]
pub(crate) struct RateLimits {
    /// `/login`, `/callback`, `/logout` and `/logged-out`.
    pub(crate) auth: Governor,
    /// Every proxied route, so API traffic can't burn the login budget or the reverse.
    pub(crate) proxy: Governor,
}

impl RateLimits {
    pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
        let build = |max_attempts: u32| {
            build_governor(
                max_attempts,
                RATE_LIMIT_WINDOW_SECS,
                &config.trusted_proxies,
            )
        };
        Ok(Self {
            auth: build(config.rate_limit_max_attempts)?,
            proxy: build(config.rate_limit_proxy_max_attempts)?,
        })
    }

    /// Forgets clients whose bucket has refilled and hands back the memory. The
    /// limiter keeps every key it has seen until this runs.
    pub(crate) fn retain_recent(&self) {
        for governor in [&self.auth, &self.proxy] {
            governor.limiter().retain_recent();
            governor.limiter().shrink_to_fit();
        }
    }
}
