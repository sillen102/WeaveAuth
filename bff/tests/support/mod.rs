//! A stub Hydra and helpers that drive bff's routers through a whole login.
#![allow(dead_code)]

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;
use weaveauth_bff::config::{Config, RouteConfig};
use weaveauth_bff::server::apps;

pub const HYDRA_PUBLIC_URL: &str = "http://hydra.test";
pub const CLIENT_ID: &str = "weaveauth-bff";
pub const CLIENT_SECRET: &str = "test-secret";
pub const INTERNAL_API_KEY: &str = "internal-api-key";
pub const KID: &str = "test-kid";
pub const HYDRA_KEY: &str = include_str!("../fixtures/hydra_key.pem");
pub const OTHER_KEY: &str = include_str!("../fixtures/other_key.pem");
const HYDRA_JWK: &str = include_str!("../fixtures/hydra_jwk.json");

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `claims` as a JWT signed by Hydra's key.
pub fn sign(claims: &serde_json::Value) -> String {
    sign_with(HYDRA_KEY, claims)
}

pub fn sign_with(pem: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

pub fn at_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(access_token.as_bytes())[..16])
}

/// What a code Hydra issued stands for.
pub struct Grant {
    pub nonce: String,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub sub: Uuid,
    pub sid: Option<String>,
}

pub struct TokenRequest {
    pub authorization: Option<String>,
    pub form: HashMap<String, String>,
}

pub struct HydraState {
    pub codes: HashMap<String, Grant>,
    /// Live refresh tokens, and whom they belong to.
    pub refresh_tokens: HashMap<String, (Uuid, Option<String>)>,
    /// Refresh tokens that were redeemed, and whose redeeming again revokes the chain.
    pub spent_refresh_tokens: HashSet<String>,
    pub chain_revoked: bool,
    pub requests: Vec<TokenRequest>,
    pub refresh_calls: usize,
    pub refresh_delay: Duration,
    /// When set, a refresh answers only once a permit is added: the response is decided
    /// first, like a Hydra whose answer is slow to arrive.
    pub refresh_gate: Option<Arc<tokio::sync::Semaphore>>,
    /// How many refresh requests are being answered right now, and the most there were at once.
    pub refreshes_in_flight: usize,
    pub max_refreshes_in_flight: usize,
    /// Status and OAuth `error` the next refresh calls answer with, before succeeding again.
    pub refresh_failures: VecDeque<(u16, &'static str)>,
    pub refresh_returns_id_token: bool,
    pub revoked: Vec<String>,
    pub revoke_status: u16,
    pub access_ttl_secs: i64,
    pub issued: usize,
    pub jwks_fetches: usize,
    /// Replaces the `nonce` of the next id_tokens issued.
    pub nonce_override: Option<String>,
    /// Replaces the `aud` of the next id_tokens issued.
    pub aud_override: Option<serde_json::Value>,
    /// Replaces the `iss` of the next id_tokens issued.
    pub iss_override: Option<String>,
    /// Signs the next id_tokens with a key Hydra does not publish.
    pub sign_with_other_key: bool,
    pub no_refresh_token: bool,
    /// Status and OAuth `error` the code exchange answers with.
    pub code_status: Option<(u16, &'static str)>,
}

#[derive(Clone)]
pub struct StubHydra {
    pub url: String,
    pub state: Arc<Mutex<HydraState>>,
}

impl StubHydra {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(HydraState {
            codes: HashMap::new(),
            refresh_tokens: HashMap::new(),
            spent_refresh_tokens: HashSet::new(),
            chain_revoked: false,
            requests: Vec::new(),
            refresh_calls: 0,
            refresh_delay: Duration::ZERO,
            refresh_gate: None,
            refreshes_in_flight: 0,
            max_refreshes_in_flight: 0,
            refresh_failures: VecDeque::new(),
            refresh_returns_id_token: true,
            revoked: Vec::new(),
            revoke_status: 200,
            access_ttl_secs: 900,
            issued: 0,
            jwks_fetches: 0,
            nonce_override: None,
            aud_override: None,
            iss_override: None,
            sign_with_other_key: false,
            no_refresh_token: false,
            code_status: None,
        }));
        let router = Router::new()
            .route("/.well-known/jwks.json", get(jwks))
            .route("/oauth2/token", post(token))
            .route("/oauth2/revoke", post(revoke))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, state }
    }

    pub fn with<R>(&self, change: impl FnOnce(&mut HydraState) -> R) -> R {
        change(&mut self.state.lock().unwrap())
    }

    /// Plays Hydra's authorization endpoint for the browser URL bff redirected to: remembers
    /// the request and returns the code Hydra would send back.
    pub fn grant(&self, authorize_url: &str, sub: Uuid, sid: Option<&str>) -> String {
        let url = url::Url::parse(authorize_url).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            HYDRA_PUBLIC_URL,
            "{authorize_url}"
        );
        assert_eq!(url.path(), "/oauth2/auth");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let code = format!("code-{}", Uuid::new_v4());
        self.with(|state| {
            state.codes.insert(
                code.clone(),
                Grant {
                    nonce: query["nonce"].clone(),
                    code_challenge: query["code_challenge"].clone(),
                    redirect_uri: query["redirect_uri"].clone(),
                    sub,
                    sid: sid.map(str::to_string),
                },
            );
        });
        code
    }
}

async fn jwks(State(state): State<Arc<Mutex<HydraState>>>) -> Json<serde_json::Value> {
    state.lock().unwrap().jwks_fetches += 1;
    let mut jwk: serde_json::Value = serde_json::from_str(HYDRA_JWK).unwrap();
    jwk["kid"] = KID.into();
    Json(serde_json::json!({ "keys": [jwk] }))
}

fn oauth_error(status: u16, error: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        Json(serde_json::json!({ "error": error })),
    )
        .into_response()
}

fn expected_authorization() -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    )
}

async fn token(
    State(state): State<Arc<Mutex<HydraState>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let (response, delay, gate, is_refresh) = {
        let mut state = state.lock().unwrap();
        state.requests.push(TokenRequest {
            authorization: authorization.clone(),
            form: form.clone(),
        });
        let is_refresh = form.get("grant_type").map(String::as_str) == Some("refresh_token");
        let (mut delay, mut gate) = (Duration::ZERO, None);
        if is_refresh {
            state.refresh_calls += 1;
            state.refreshes_in_flight += 1;
            state.max_refreshes_in_flight =
                state.max_refreshes_in_flight.max(state.refreshes_in_flight);
            delay = state.refresh_delay;
            gate = state.refresh_gate.clone();
        }
        (
            answer(&mut state, authorization, &form),
            delay,
            gate,
            is_refresh,
        )
    };
    // The answer is decided before the wait, like a Hydra whose response is slow to arrive.
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Some(gate) = gate {
        gate.acquire().await.unwrap().forget();
    }
    if is_refresh {
        state.lock().unwrap().refreshes_in_flight -= 1;
    }
    response
}

fn answer(
    state: &mut HydraState,
    authorization: Option<String>,
    form: &HashMap<String, String>,
) -> Response {
    if authorization != Some(expected_authorization()) {
        return oauth_error(401, "invalid_client");
    }
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            if let Some((status, error)) = state.code_status {
                return oauth_error(status, error);
            }
            let Some(grant) = form.get("code").and_then(|code| state.codes.remove(code)) else {
                return oauth_error(400, "invalid_grant");
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if challenge != grant.code_challenge
                || form.get("redirect_uri") != Some(&grant.redirect_uri)
            {
                return oauth_error(400, "invalid_grant");
            }
            let nonce = state.nonce_override.clone().unwrap_or(grant.nonce);
            issue(state, grant.sub, grant.sid, Some(&nonce), true)
        }
        Some("refresh_token") => {
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            if let Some((status, error)) = state.refresh_failures.pop_front() {
                return oauth_error(status, error);
            }
            if state.spent_refresh_tokens.contains(&presented) {
                state.chain_revoked = true;
                state.refresh_tokens.clear();
                return oauth_error(400, "invalid_grant");
            }
            // Without a new refresh token the old one stays valid, as with a non-rotating client.
            let known = if state.no_refresh_token {
                state.refresh_tokens.get(&presented).cloned()
            } else {
                state.refresh_tokens.remove(&presented)
            };
            let Some((sub, sid)) = known else {
                return oauth_error(400, "invalid_grant");
            };
            if !state.no_refresh_token {
                state.spent_refresh_tokens.insert(presented);
            }
            let with_id_token = state.refresh_returns_id_token;
            issue(state, sub, sid, None, with_id_token)
        }
        _ => oauth_error(400, "unsupported_grant_type"),
    }
}

fn issue(
    state: &mut HydraState,
    sub: Uuid,
    sid: Option<String>,
    nonce: Option<&str>,
    with_id_token: bool,
) -> Response {
    state.issued += 1;
    let n = state.issued;
    let access_token = format!("access-{n}");
    let refresh_token = format!("refresh-{n}");
    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": state.access_ttl_secs,
        "scope": "openid offline_access",
    });
    if !state.no_refresh_token {
        state
            .refresh_tokens
            .insert(refresh_token.clone(), (sub, sid.clone()));
        body["refresh_token"] = refresh_token.into();
    }
    if with_id_token {
        let mut claims = serde_json::json!({
            "iss": state.iss_override.clone().unwrap_or_else(|| HYDRA_PUBLIC_URL.to_string()),
            "aud": state.aud_override.clone().unwrap_or_else(|| serde_json::json!([CLIENT_ID])),
            "sub": sub,
            "iat": now(),
            "exp": now() + 3600,
            "at_hash": at_hash(&access_token),
        });
        if let Some(nonce) = nonce {
            claims["nonce"] = nonce.into();
        }
        if let Some(sid) = sid {
            claims["sid"] = sid.into();
        }
        let pem = if state.sign_with_other_key {
            OTHER_KEY
        } else {
            HYDRA_KEY
        };
        body["id_token"] = sign_with(pem, &claims).into();
    }
    Json(body).into_response()
}

async fn revoke(
    State(state): State<Arc<Mutex<HydraState>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut state = state.lock().unwrap();
    let authorized = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(&expected_authorization());
    if !authorized {
        return oauth_error(401, "invalid_client");
    }
    let token = form.get("token").cloned().unwrap_or_default();
    state.refresh_tokens.remove(&token);
    state.revoked.push(token);
    StatusCode::from_u16(state.revoke_status)
        .unwrap()
        .into_response()
}

pub fn config(hydra: &StubHydra) -> Config {
    Config {
        bff_url: "http://bff.test".into(),
        hydra_public_url: HYDRA_PUBLIC_URL.into(),
        hydra_internal_url: hydra.url.clone(),
        bff_client_id: CLIENT_ID.into(),
        bff_client_secret: CLIENT_SECRET.to_string().into(),
        internal_api_key: INTERNAL_API_KEY.to_string().into(),
        hydra_refresh_token_ttl_secs: 3600,
        redirect_uri_allowlist: vec![
            "http://app.test/".into(),
            "http://app.test/dashboard".into(),
        ],
        trusted_origins: vec!["http://app.test".into()],
        rate_limit_max_attempts: 1000,
        rate_limit_proxy_max_attempts: 1000,
        ..Config::default()
    }
}

/// bff's two routers over one state, and the Hydra behind them.
#[derive(Clone)]
pub struct Bff {
    pub public: Router,
    pub internal: Router,
    pub hydra: StubHydra,
}

impl Bff {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(change: impl FnOnce(&mut Config)) -> Self {
        let hydra = StubHydra::start().await;
        let mut config = config(&hydra);
        change(&mut config);
        let (public, internal) = apps(config).unwrap();
        Self {
            public,
            internal,
            hydra,
        }
    }

    /// Like [`Bff::start`], with `/api` proxied to an upstream that echoes the bearer token.
    pub async fn start_proxied() -> Self {
        let upstream = stub_upstream().await;
        Self::start_with(|config| config.routes = vec![api_route(upstream)]).await
    }

    /// `GET /api/whoami` with `cookie`: the upstream answers with the bearer token it saw.
    pub async fn whoami(&self, cookie: &str) -> Response {
        self.get("/api/whoami", Some(cookie)).await
    }

    pub async fn send(&self, req: Request<Body>) -> Response {
        self.public
            .clone()
            .oneshot(with_test_peer(req))
            .await
            .unwrap()
    }

    pub async fn send_internal(&self, req: Request<Body>) -> Response {
        self.internal.clone().oneshot(req).await.unwrap()
    }

    pub async fn get(&self, uri: &str, cookie: Option<&str>) -> Response {
        let mut req = Request::get(uri);
        if let Some(cookie) = cookie {
            req = req.header("cookie", cookie);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    /// `GET /login?redirect_uri=...`.
    pub async fn start_login(&self, redirect_uri: &str) -> Response {
        let encoded: String =
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect();
        self.get(&format!("/login?redirect_uri={encoded}"), None)
            .await
    }

    /// Drives a whole login as `sub` and returns the session it ended in.
    pub async fn login(&self, sub: Uuid, sid: Option<&str>) -> Session {
        let started = self.start_login("http://app.test/").await;
        assert_eq!(started.status(), StatusCode::SEE_OTHER, "/login");
        let authorize_url = location(&started);
        let login_cookie = cookie_pair(&started, "wa_login");
        let state = query_of(&authorize_url)["state"].clone();
        let code = self.hydra.grant(&authorize_url, sub, sid);

        let response = self
            .get(
                &format!("/callback?code={code}&state={state}"),
                Some(&login_cookie),
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "/callback");
        assert_eq!(location(&response), "http://app.test/");
        Session {
            cookie: cookie_pair(&response, "wa_session"),
            user_id: sub,
        }
    }
}

pub struct Session {
    /// `wa_session=<id>`, as a `Cookie` header value.
    pub cookie: String,
    pub user_id: Uuid,
}

pub fn with_test_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

pub fn location(response: &Response) -> String {
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

pub fn query_of(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

pub fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect()
}

/// The full `Set-Cookie` value for `name`, if the response sets it.
pub fn set_cookie(response: &Response, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
}

/// `name=value` of the cookie the response sets, as a `Cookie` header value.
pub fn cookie_pair(response: &Response, name: &str) -> String {
    set_cookie(response, name)
        .unwrap_or_else(|| panic!("no {name} cookie in {:?}", set_cookies(response)))
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

pub async fn body_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// An upstream that echoes the bearer token it was called with.
pub async fn stub_upstream() -> String {
    let router = Router::new().route(
        "/whoami",
        get(|headers: HeaderMap| async move {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
}

pub fn api_route(upstream: String) -> RouteConfig {
    RouteConfig {
        path_prefix: "/api".into(),
        upstream_url: upstream,
    }
}

/// The claims of a valid back-channel logout token for `sub` and `sid`.
pub fn logout_claims(sub: Option<Uuid>, sid: Option<&str>) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "iss": HYDRA_PUBLIC_URL,
        "aud": [CLIENT_ID],
        "iat": now(),
        "jti": Uuid::new_v4().to_string(),
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    if let Some(sub) = sub {
        claims["sub"] = sub.to_string().into();
    }
    if let Some(sid) = sid {
        claims["sid"] = sid.into();
    }
    claims
}

pub fn form_body(fields: &[(&str, &str)]) -> Body {
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        body.append_pair(name, value);
    }
    Body::from(body.finish())
}

impl Bff {
    /// `POST /backchannel-logout` on the internal listener, the way Hydra sends it.
    pub async fn backchannel_logout(&self, logout_token: &str) -> Response {
        self.send_internal(
            Request::post("/backchannel-logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form_body(&[("logout_token", logout_token)]))
                .unwrap(),
        )
        .await
    }

    /// `POST /internal/revoke` with the given `Authorization` header, if any.
    pub async fn internal_revoke(&self, authorization: Option<&str>, body: &str) -> Response {
        let mut req = Request::post("/internal/revoke").header("content-type", "application/json");
        if let Some(authorization) = authorization {
            req = req.header("authorization", authorization);
        }
        self.send_internal(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    /// `POST /logout` from `origin`, with the session cookie, if any.
    pub async fn logout(
        &self,
        origin: Option<&str>,
        cookie: Option<&str>,
        query: &str,
    ) -> Response {
        let mut req = Request::post(format!("/logout{query}"));
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        if let Some(cookie) = cookie {
            req = req.header("cookie", cookie);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }
}
