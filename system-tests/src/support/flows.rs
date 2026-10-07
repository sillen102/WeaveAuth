//! Driving the browser flows (what `ory/checks/run_checks.py` does with its stand-in browser):
//! Kratos flow objects through login's proxy, form posts, mailed codes, and bff/Hydra OAuth2.

use super::browser::{Browser, Follow, Resp};
use super::stack::{BFF_CLIENT_ID, BFF_CLIENT_SECRET, REDIRECT_URI, Stack};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const PASSWORD: &str = "correct-Horse-battery-9!";

pub fn unique_email(prefix: &str) -> String {
    format!(
        "{prefix}-{}@example.test",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

// --- Kratos flow objects ------------------------------------------------------------------

/// The values of a flow's input nodes (the default group and `method`'s), as a browser submits them.
pub fn form_values(flow: &Value, method: &str) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for node in flow["ui"]["nodes"].as_array().into_iter().flatten() {
        let attributes = &node["attributes"];
        let Some(name) = attributes["name"].as_str().filter(|n| !n.is_empty()) else {
            continue;
        };
        let group = node["group"].as_str().unwrap_or_default();
        let submit = matches!(attributes["type"].as_str(), Some("submit" | "button"));
        if node["type"] != "input" || submit || (group != "default" && group != method) {
            continue;
        }
        match &attributes["value"] {
            Value::Null => {}
            Value::String(value) => values.push((name.to_string(), value.clone())),
            other => values.push((name.to_string(), other.to_string())),
        }
    }
    values
}

pub async fn flow(stack: &Stack, b: &Browser, kind: &str, id: &str) -> Value {
    let resp = b
        .get_json(&format!(
            "{}/self-service/{kind}/flows?id={id}",
            stack.login_url
        ))
        .await;
    assert_eq!(resp.status, 200, "fetching {kind} flow {id}: {}", resp.body);
    resp.json()
}

/// The flow a page was opened for (`?flow=ID`).
pub async fn flow_of(stack: &Stack, b: &Browser, kind: &str, page: &Resp) -> Value {
    let id = page
        .query("flow")
        .unwrap_or_else(|| panic!("{} has no flow id (status {})", page.url, page.status));
    flow(stack, b, kind, &id).await
}

/// Starts a browser flow of `kind`, carrying Hydra's login challenge when there is one.
pub async fn new_flow(stack: &Stack, b: &Browser, kind: &str, challenge: Option<&str>) -> Value {
    let mut url = format!("{}/self-service/{kind}/browser", stack.login_url);
    if let Some(challenge) = challenge {
        url = format!("{url}?login_challenge={challenge}");
    }
    let page = b.get(&url, Follow::All).await;
    flow_of(stack, b, kind, &page).await
}

/// Posts `method`'s form of `flow`, with `overrides` replacing or adding values.
pub async fn submit(
    b: &Browser,
    flow: &Value,
    method: &str,
    overrides: &[(&str, &str)],
    follow: Follow<'_>,
) -> Resp {
    let mut form = form_values(flow, method);
    form.retain(|(name, _)| !overrides.iter().any(|(o, _)| o == name));
    form.extend(
        overrides
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    form.push(("method".into(), method.into()));
    let action = flow["ui"]["action"].as_str().expect("flow action");
    b.post_form(action, &form, &[], follow).await
}

/// Starts the sign-in with a provider from a login (or registration) flow.
pub async fn provider(b: &Browser, flow: &Value, provider: &str, follow: Follow<'_>) -> Resp {
    let csrf = form_values(flow, "oidc")
        .into_iter()
        .find(|(name, _)| name == "csrf_token")
        .map(|(_, value)| value)
        .unwrap_or_default();
    let form = vec![
        ("provider".to_string(), provider.to_string()),
        ("csrf_token".into(), csrf),
    ];
    let action = flow["ui"]["action"].as_str().expect("flow action");
    b.post_form(action, &form, &[], follow).await
}

/// The text of the first message of a flow, for assertions on what the user is told.
pub fn first_message(flow: &Value) -> String {
    flow["ui"]["messages"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

// --- mail -----------------------------------------------------------------------------------

/// The 6-digit code of the newest mail to `email` whose subject contains `subject`, once at least
/// `count` such mails have arrived.
pub async fn mail_code(stack: &Stack, email: &str, subject: &str, count: usize) -> String {
    for _ in 0..60 {
        let listing: Value = stack
            .http
            .get(format!("{}/api/v1/messages", stack.mail_api))
            .send()
            .await
            .expect("mailpit")
            .json()
            .await
            .expect("mailpit json");
        let matching: Vec<&Value> = listing["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|m| {
                m["To"][0]["Address"] == email
                    && m["Subject"].as_str().is_some_and(|s| s.contains(subject))
            })
            .collect();
        if matching.len() >= count {
            let id = matching[0]["ID"].as_str().expect("mail id");
            let message: Value = stack
                .http
                .get(format!("{}/api/v1/message/{id}", stack.mail_api))
                .send()
                .await
                .expect("mailpit")
                .json()
                .await
                .expect("mailpit json");
            let text = message["Text"].as_str().unwrap_or_default();
            return six_digits(text).unwrap_or_else(|| panic!("no code in mail: {text}"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no {subject:?} mail for {email}");
}

/// The first run of exactly six digits that stands alone (like `\b\d{6}\b`): a longer number
/// or a hex id such as the address in the mail's greeting can contain six digits too.
fn six_digits(text: &str) -> Option<String> {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let chars: Vec<char> = text.chars().collect();
    let mut start = 0;
    while start < chars.len() {
        if !chars[start].is_ascii_digit() {
            start += 1;
            continue;
        }
        let end = chars[start..]
            .iter()
            .position(|c| !c.is_ascii_digit())
            .map_or(chars.len(), |n| start + n);
        let before = start.checked_sub(1).and_then(|i| chars.get(i));
        let after = chars.get(end);
        if end - start == 6 && !before.is_some_and(|c| word(*c)) && !after.is_some_and(|c| word(*c))
        {
            return Some(chars[start..end].iter().collect());
        }
        start = end;
    }
    None
}

// --- login through bff ------------------------------------------------------------------------

/// `GET /login` on bff: ends on login's page for a new browser, or on the redirect to
/// `REDIRECT_URI` for one that is signed in.
pub async fn bff_login(stack: &Stack, b: &Browser) -> Resp {
    b.get(
        &format!(
            "{}/login?redirect_uri={}",
            stack.bff_url,
            encode(REDIRECT_URI)
        ),
        Follow::Until(REDIRECT_URI),
    )
    .await
}

pub fn landed_on_app(resp: &Resp) -> bool {
    resp.redirect_target()
        .is_some_and(|target| target.as_str().starts_with(REDIRECT_URI))
}

/// Whether `b` holds a bff session.
pub fn has_session(stack: &Stack, b: &Browser) -> bool {
    b.cookie(&stack.bff_url, "wa_session").is_some()
}

/// Signs in with a password through bff; the response is the one redirecting to the app.
pub async fn login_via_bff(stack: &Stack, b: &Browser, email: &str, password: &str) -> Resp {
    let page = bff_login(stack, b).await;
    let lf = flow_of(stack, b, "login", &page).await;
    submit(
        b,
        &lf,
        "password",
        &[("identifier", email), ("password", password)],
        Follow::Until(REDIRECT_URI),
    )
    .await
}

/// A browser signed in through bff, which must have worked.
pub async fn session_for(stack: &Stack, email: &str, password: &str) -> Browser {
    let b = stack.browser();
    let resp = login_via_bff(stack, &b, email, password).await;
    assert!(
        landed_on_app(&resp),
        "login ended at {} ({})",
        resp.url,
        resp.status
    );
    assert!(has_session(stack, &b), "no wa_session after login");
    b
}

/// Registers with a password up to the point where the flow's own outcome shows: a redirect to
/// the app (signed in at once) or the verification page.
pub async fn register_via_bff(stack: &Stack, b: &Browser, email: &str, password: &str) -> Resp {
    let page = bff_login(stack, b).await;
    let lf = flow_of(stack, b, "login", &page).await;
    let challenge = lf["oauth2_login_challenge"]
        .as_str()
        .expect("login challenge");
    let rf = new_flow(stack, b, "registration", Some(challenge)).await;
    submit(
        b,
        &rf,
        "profile",
        &[
            ("traits.email", email),
            ("traits.first_name", "System"),
            ("traits.last_name", "Test"),
            ("traits.phone_number", "+46701234567"),
        ],
        Follow::No,
    )
    .await;
    let rf = flow(
        stack,
        b,
        "registration",
        rf["id"].as_str().expect("flow id"),
    )
    .await;
    submit(
        b,
        &rf,
        "password",
        &[("password", password)],
        Follow::Until(REDIRECT_URI),
    )
    .await
}

/// Enters the mailed verification code on the verification page `page`.
pub async fn verify_email(stack: &Stack, b: &Browser, page: &Resp, email: &str) -> Resp {
    let vf = flow_of(stack, b, "verification", page).await;
    let code = mail_code(stack, email, "verification code", 1).await;
    let resp = submit(
        b,
        &vf,
        "code",
        &[("code", &code)],
        Follow::Until(REDIRECT_URI),
    )
    .await;
    if resp.status == 200 {
        // Still on the page: say what Kratos told the user.
        let after = flow_of(stack, b, "verification", &resp).await;
        eprintln!(
            "verification of {email} with code {code}: state {} messages {}",
            after["state"], after["ui"]["messages"]
        );
    }
    resp
}

/// A request through bff's proxy to the upstream stub, with `b`'s session.
pub async fn whoami(stack: &Stack, b: &Browser) -> Resp {
    b.get(&format!("{}/downstream/whoami", stack.bff_url), Follow::No)
        .await
}

/// The access token the upstream stub received through bff.
pub async fn upstream_token(stack: &Stack, b: &Browser) -> String {
    let resp = whoami(stack, b).await;
    assert_eq!(resp.status, 200, "proxied call: {}", resp.body);
    let seen = resp.json();
    assert_eq!(seen["cookie"], false, "the session cookie leaked upstream");
    seen["authorization"]
        .as_str()
        .and_then(|a| a.strip_prefix("Bearer "))
        .expect("bearer token upstream")
        .to_string()
}

// --- OAuth2 straight against Hydra ----------------------------------------------------------------

pub fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn callback(stack: &Stack) -> String {
    format!("{}/callback", stack.bff_url)
}

/// `/oauth2/auth` as bff's client, without bff: stops at the redirect to bff's callback, so the
/// test holds the code. Returns that response and the PKCE verifier.
pub async fn direct_authorize(stack: &Stack, b: &Browser) -> (Resp, String) {
    let (verifier, challenge) = pkce();
    let url = format!(
        "{}/oauth2/auth?client_id={BFF_CLIENT_ID}&response_type=code&scope=openid+offline_access\
         &redirect_uri={}&state=st12345678&code_challenge={challenge}&code_challenge_method=S256\
         &audience=weaveauth",
        stack.login_url,
        encode(&callback(stack)),
    );
    (b.get(&url, Follow::Until(&callback(stack))).await, verifier)
}

async fn token_request(stack: &Stack, form: &[(&str, &str)]) -> (u16, Value) {
    let response = stack
        .http
        .post(format!("{}/oauth2/token", stack.hydra_public))
        .basic_auth(BFF_CLIENT_ID, Some(BFF_CLIENT_SECRET))
        .form(form)
        .send()
        .await
        .expect("token request");
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// Tokens for `email` straight from Hydra: signs in if the browser isn't yet, takes the code at
/// bff's callback and exchanges it as the bff client would.
pub async fn direct_tokens(stack: &Stack, b: &Browser, credentials: Option<(&str, &str)>) -> Value {
    let (mut resp, verifier) = direct_authorize(stack, b).await;
    if let (false, Some((email, password))) = (is_callback(stack, &resp), credentials) {
        let lf = flow_of(stack, b, "login", &resp).await;
        resp = submit(
            b,
            &lf,
            "password",
            &[("identifier", email), ("password", password)],
            Follow::Until(&callback(stack)),
        )
        .await;
    }
    assert!(
        is_callback(stack, &resp),
        "authorize ended at {} ({})",
        resp.url,
        resp.status
    );
    let target = resp.redirect_target().expect("redirect");
    let code = target
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code at the callback");
    let (status, tokens) = token_request(
        stack,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &callback(stack)),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, 200, "code exchange: {tokens}");
    tokens
}

fn is_callback(stack: &Stack, resp: &Resp) -> bool {
    resp.redirect_target()
        .is_some_and(|t| t.as_str().starts_with(&callback(stack)))
}

/// A refresh grant at Hydra: the status and body.
pub async fn refresh(stack: &Stack, refresh_token: &str) -> (u16, Value) {
    token_request(
        stack,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
    )
    .await
}

// --- JWTs -----------------------------------------------------------------------------------------

/// The payload of a JWT, unverified.
pub fn jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| STANDARD_NO_PAD.decode(payload))
        .expect("JWT base64");
    serde_json::from_slice(&bytes).expect("JWT JSON")
}

/// Verifies an access token against Hydra's JWKS (signature, expiry, issuer, audience) and
/// returns its claims.
pub async fn verified_claims(stack: &Stack, token: &str) -> Value {
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    let jwks: JwkSet = stack
        .http
        .get(format!("{}/.well-known/jwks.json", stack.hydra_public))
        .send()
        .await
        .expect("jwks")
        .json()
        .await
        .expect("jwks json");
    let kid = decode_header(token).expect("header").kid.expect("kid");
    let jwk = jwks.find(&kid).expect("signing key in Hydra's JWKS");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["weaveauth"]);
    validation.set_issuer(&[stack.login_url.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("jwk"),
        &validation,
    )
    .unwrap_or_else(|e| panic!("access token does not verify: {e}"))
    .claims
}

/// Whether `b` holds a live Kratos session (the logout flow only starts for one).
pub async fn kratos_session_active(stack: &Stack, b: &Browser) -> bool {
    let resp = b
        .get_json(&format!("{}/self-service/logout/browser", stack.login_url))
        .await;
    resp.status == 200
}
