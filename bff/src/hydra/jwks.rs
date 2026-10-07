use jsonwebtoken::jwk::JwkSet;
use openidconnect::core::CoreJsonWebKeySet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum JwksError {
    #[error("JWKS request failed: {0}")]
    Unreachable(String),
    #[error("JWKS endpoint answered {0}")]
    Unavailable(u16),
    #[error("JWKS unreadable: {0}")]
    Unreadable(String),
    #[error("no key {0:?} in the JWKS")]
    UnknownKey(String),
    /// A fetch was attempted less than the minimum refresh interval ago, so none was made.
    #[error("JWKS was fetched too recently to fetch again")]
    Throttled,
}

/// Hydra's signing keys, once as `openidconnect` verifies id_tokens with them and once as
/// `jsonwebtoken` verifies logout tokens with them.
pub(crate) struct Keys {
    pub(crate) openid: CoreJsonWebKeySet,
    pub(crate) jwt: JwkSet,
}

impl Keys {
    fn parse(body: &[u8]) -> Result<Self, JwksError> {
        let unreadable = |error: serde_json::Error| JwksError::Unreadable(error.to_string());
        Ok(Self {
            openid: serde_json::from_slice(body).map_err(unreadable)?,
            jwt: serde_json::from_slice(body).map_err(unreadable)?,
        })
    }

    fn has_kid(&self, kid: &str) -> bool {
        self.jwt.find(kid).is_some()
    }
}

/// How long fetched keys are trusted, so a key Hydra removed (after a compromise) stops
/// verifying without a bff restart.
const MAX_AGE: Duration = Duration::from_secs(60 * 60);

struct Cached {
    keys: Option<(Arc<Keys>, Instant)>,
    last_attempt: Option<Instant>,
}

/// Hydra's JWKS, fetched on first use, again when a token names a `kid` it doesn't hold
/// (Hydra rotated) and again once the keys are older than [`MAX_AGE`]. The fetches are
/// single-flight, and at most one is made per `min_refresh`, so tokens with made-up `kid`s
/// can't turn into a flood of fetches.
pub(crate) struct JwksCache {
    url: String,
    http: reqwest::Client,
    min_refresh: Duration,
    max_age: Duration,
    cached: Mutex<Cached>,
}

impl JwksCache {
    pub(crate) fn new(url: String, http: reqwest::Client, min_refresh: Duration) -> Self {
        Self {
            url,
            http,
            min_refresh,
            max_age: MAX_AGE,
            cached: Mutex::new(Cached {
                keys: None,
                last_attempt: None,
            }),
        }
    }

    #[cfg(test)]
    fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// The keys to verify a token naming `kid` with: the cached ones if they are not too old
    /// and hold it (or if the token names none), else freshly fetched. When that fetch can't be
    /// made or fails, keys older than [`MAX_AGE`] that hold `kid` still serve until they are
    /// twice that old, so a short Hydra outage doesn't fail every check.
    pub(crate) async fn keys_for(&self, kid: Option<&str>) -> Result<Arc<Keys>, JwksError> {
        let mut cached = self.cached.lock().await;
        if let Some((keys, fetched_at)) = &cached.keys
            && fetched_at.elapsed() < self.max_age
            && kid.is_none_or(|kid| keys.has_kid(kid))
        {
            return Ok(keys.clone());
        }
        let stale = match (&cached.keys, kid) {
            (Some((keys, fetched_at)), Some(kid))
                if keys.has_kid(kid) && fetched_at.elapsed() < self.max_age * 2 =>
            {
                Some(keys.clone())
            }
            _ => None,
        };
        if cached
            .last_attempt
            .is_some_and(|attempt| attempt.elapsed() < self.min_refresh)
        {
            return stale.ok_or(JwksError::Throttled);
        }
        cached.last_attempt = Some(Instant::now());
        let keys = match self.fetch().await {
            Ok(keys) => Arc::new(keys),
            Err(error) => return stale.ok_or(error),
        };
        cached.keys = Some((keys.clone(), Instant::now()));
        match kid {
            Some(kid) if !keys.has_kid(kid) => Err(JwksError::UnknownKey(kid.to_string())),
            _ => Ok(keys),
        }
    }

    async fn fetch(&self) -> Result<Keys, JwksError> {
        let response = self.http.get(&self.url).send().await.map_err(|error| {
            JwksError::Unreachable(common::error::cause_chain(&error.without_url()))
        })?;
        if !response.status().is_success() {
            return Err(JwksError::Unavailable(response.status().as_u16()));
        }
        let body = response.bytes().await.map_err(|error| {
            JwksError::Unreachable(common::error::cause_chain(&error.without_url()))
        })?;
        Keys::parse(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn jwks_with(kids: &[&str]) -> serde_json::Value {
        let jwk: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/hydra_jwk.json")).unwrap();
        let keys: Vec<_> = kids
            .iter()
            .map(|kid| {
                let mut key = jwk.clone();
                key["kid"] = (*kid).into();
                key
            })
            .collect();
        serde_json::json!({ "keys": keys })
    }

    /// A JWKS endpoint serving whatever `current` holds, counting the fetches.
    async fn jwks_server(
        current: Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> (String, Arc<AtomicUsize>) {
        let fetches = Arc::new(AtomicUsize::new(0));
        let counter = fetches.clone();
        let router = Router::new().route(
            "/jwks",
            get(move || {
                let current = current.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Slow enough for concurrent callers to pile up behind the first fetch.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    axum::Json(current.lock().unwrap().clone())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        (url, fetches)
    }

    fn cache(url: String, min_refresh: Duration) -> JwksCache {
        JwksCache::new(url, reqwest::Client::new(), min_refresh)
    }

    #[tokio::test]
    async fn the_keys_are_fetched_once_and_served_from_the_cache_while_the_kid_is_known() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, fetches) = jwks_server(current).await;
        let cache = cache(url, Duration::ZERO);

        cache.keys_for(Some("k1")).await.unwrap();
        cache.keys_for(Some("k1")).await.unwrap();
        cache.keys_for(None).await.unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_and_finds_a_rotated_in_key() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, fetches) = jwks_server(current.clone()).await;
        let cache = cache(url, Duration::ZERO);
        cache.keys_for(Some("k1")).await.unwrap();

        *current.lock().unwrap() = jwks_with(&["k1", "k2"]);
        let keys = cache.keys_for(Some("k2")).await.unwrap();

        assert!(keys.has_kid("k2"));
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_kid_that_is_still_unknown_after_a_refetch_is_an_error() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, _) = jwks_server(current).await;
        let cache = cache(url, Duration::ZERO);

        let error = cache.keys_for(Some("nope")).await.err().unwrap();

        assert_eq!(error, JwksError::UnknownKey("nope".into()));
    }

    #[tokio::test]
    async fn unknown_kids_cannot_make_more_than_one_fetch_per_interval() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, fetches) = jwks_server(current).await;
        let cache = cache(url, Duration::from_secs(3600));

        let first = cache.keys_for(Some("a")).await.err().unwrap();
        let second = cache.keys_for(Some("b")).await.err().unwrap();
        // The cache still serves a kid it holds.
        cache.keys_for(Some("k1")).await.unwrap();

        assert_eq!(first, JwksError::UnknownKey("a".into()));
        assert_eq!(second, JwksError::Throttled);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keys_past_their_max_age_are_fetched_again_so_a_removed_key_stops_verifying() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1", "k2"])));
        let (url, fetches) = jwks_server(current.clone()).await;
        let cache = cache(url, Duration::ZERO).with_max_age(Duration::from_millis(1000));
        cache.keys_for(Some("k2")).await.unwrap();
        cache.keys_for(Some("k2")).await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        // Hydra drops k2 (a key removed after a compromise).
        *current.lock().unwrap() = jwks_with(&["k1"]);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let error = cache.keys_for(Some("k2")).await.err().unwrap();

        assert_eq!(error, JwksError::UnknownKey("k2".into()));
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        cache.keys_for(Some("k1")).await.unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_refetch_serves_stale_keys_that_hold_the_kid_until_twice_the_max_age() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, _) = jwks_server(current).await;
        let mut cache = cache(url, Duration::ZERO).with_max_age(Duration::from_millis(1000));
        cache.keys_for(Some("k1")).await.unwrap();
        cache.url = "http://127.0.0.1:1/jwks".into();

        tokio::time::sleep(Duration::from_millis(1250)).await;
        cache.keys_for(Some("k1")).await.unwrap();
        // A kid the stale keys don't hold gets the fetch error.
        assert!(matches!(
            cache.keys_for(Some("nope")).await.err().unwrap(),
            JwksError::Unreachable(_)
        ));

        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(matches!(
            cache.keys_for(Some("k1")).await.err().unwrap(),
            JwksError::Unreachable(_)
        ));
    }

    #[tokio::test]
    async fn a_throttled_refetch_serves_stale_keys_that_hold_the_kid_and_throttles_the_rest() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, fetches) = jwks_server(current).await;
        let cache = cache(url, Duration::from_secs(3600)).with_max_age(Duration::from_millis(1000));
        cache.keys_for(Some("k1")).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1250)).await;
        cache.keys_for(Some("k1")).await.unwrap();
        let unknown = cache.keys_for(Some("nope")).await.err().unwrap();

        assert_eq!(unknown, JwksError::Throttled);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(
            cache.keys_for(Some("k1")).await.err().unwrap(),
            JwksError::Throttled
        );
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_fetch() {
        let current = Arc::new(std::sync::Mutex::new(jwks_with(&["k1"])));
        let (url, fetches) = jwks_server(current).await;
        let cache = Arc::new(cache(url, Duration::ZERO));

        let calls: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(async move { cache.keys_for(Some("k1")).await.map(|_| ()) })
            })
            .collect();
        for call in calls {
            call.await.unwrap().unwrap();
        }

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unreachable_or_failing_endpoint_is_reported_and_tried_again_later() {
        let cache = cache("http://127.0.0.1:1/jwks".into(), Duration::ZERO);
        assert!(matches!(
            cache.keys_for(None).await.err().unwrap(),
            JwksError::Unreachable(_)
        ));

        let router = Router::new().route(
            "/jwks",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        let failing = JwksCache::new(url, reqwest::Client::new(), Duration::ZERO);

        assert_eq!(
            failing.keys_for(None).await.err().unwrap(),
            JwksError::Unavailable(500)
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_jwks_is_unreadable() {
        let router = Router::new().route("/jwks", get(|| async { "not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });

        let error = cache(url, Duration::ZERO)
            .keys_for(None)
            .await
            .err()
            .unwrap();

        assert!(matches!(error, JwksError::Unreadable(_)), "{error}");
    }
}
