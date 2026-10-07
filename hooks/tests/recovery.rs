mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use support::{Call, Harness, ID, SESSION, identity_json};

const OTHER: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_2: &str = "44444444-4444-4444-8444-444444444444";

/// A Kratos stub whose active session list shrinks as sessions are revoked and whose identity
/// loses its passkey to the JSON patch, as Kratos'.
fn kratos(sessions: &[&str]) -> impl Fn(&Call) -> (u16, Value) + Send + Sync + use<> {
    let sessions: Arc<Mutex<Vec<String>>> =
        Arc::new(Mutex::new(sessions.iter().map(|s| s.to_string()).collect()));
    let passkey = Arc::new(AtomicBool::new(true));
    move |call: &Call| match (call.method.as_str(), call.path()) {
        ("GET", path) if path.ends_with("/sessions") => {
            let list: Vec<Value> = sessions
                .lock()
                .unwrap()
                .iter()
                .map(|id| json!({"id": id}))
                .collect();
            (200, Value::Array(list))
        }
        ("GET", _) => {
            let mut identity = identity_with_social_logins();
            if !passkey.load(Ordering::SeqCst) {
                identity["credentials"]
                    .as_object_mut()
                    .unwrap()
                    .remove("passkey");
            }
            (200, identity)
        }
        ("PATCH", _) => {
            // Kratos 400s a patch removing a passkey the identity no longer has.
            if passkey.swap(false, Ordering::SeqCst) {
                (200, json!({}))
            } else {
                (400, json!({}))
            }
        }
        ("PUT", _) => (200, json!({})),
        ("DELETE", path) if path.starts_with("/admin/sessions/") => {
            let id = path.rsplit('/').next().unwrap();
            sessions.lock().unwrap().retain(|s| s != id);
            (204, Value::Null)
        }
        _ => (204, Value::Null),
    }
}

/// An identity with two linked providers, as Kratos shows it with `include_credential=oidc`.
fn identity_with_social_logins() -> Value {
    let mut identity = identity_json(ID, "alice@example.com", true);
    identity["credentials"]["oidc"] = json!({
        "type": "oidc",
        "identifiers": ["google:1001", "github:2002"],
        "config": {"providers": [
            {"provider": "google", "subject": "1001"},
            {"provider": "github", "subject": "2002"},
        ]},
    });
    identity["credentials"]["passkey"] = json!({"type": "passkey", "identifiers": []});
    identity
}

async fn harness(sessions: &[&str]) -> Harness {
    Harness::with(kratos(sessions), support::no_content, support::no_content).await
}

fn recovery() -> Value {
    json!({"identity_id": ID, "session_id": SESSION})
}

fn credential_deletes(harness: &Harness) -> Vec<String> {
    harness
        .log
        .of("kratos")
        .iter()
        .filter(|c| c.method == "DELETE" && c.path().contains("/credentials/"))
        .map(|c| c.path().rsplit('/').next().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn recovery_ends_the_old_password_and_deletes_every_other_credential_including_social_logins()
{
    let harness = harness(&[]).await;

    let (status, _) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::OK);
    let kratos = harness.log.of("kratos");
    let put = kratos
        .iter()
        .find(|c| c.method == "PUT")
        .expect("the password is replaced");
    assert_eq!(put.path(), format!("/admin/identities/{ID}"));
    let password = put.body["credentials"]["password"]["config"]["password"]
        .as_str()
        .unwrap();
    assert!(password.len() >= 32, "an unguessable password");
    assert_eq!(put.body["traits"]["email"], "alice@example.com");
    assert_eq!(
        put.body["credentials"].as_object().unwrap().len(),
        1,
        "only the password is touched"
    );
    // The purge runs twice (before and after the sessions end); this is the first round.
    let mut deleted = credential_deletes(&harness);
    deleted.truncate(deleted.len() / 2);
    deleted.sort();
    assert_eq!(
        deleted,
        ["lookup_secret", "oidc", "oidc", "totp", "webauthn"]
    );
    // Each link goes by its own identifier, and only after the password is replaced, so Kratos
    // never sees the account lose its last first factor.
    let lines = harness.log.lines();
    let oidc_deletes: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("/credentials/oidc"))
        .take(2)
        .collect();
    assert_eq!(
        oidc_deletes,
        [
            &format!(
                "kratos DELETE /admin/identities/{ID}/credentials/oidc?identifier=google%3A1001"
            ),
            &format!(
                "kratos DELETE /admin/identities/{ID}/credentials/oidc?identifier=github%3A2002"
            ),
        ]
    );
    let put = lines
        .iter()
        .position(|l| l.starts_with("kratos PUT"))
        .unwrap();
    assert!(
        lines
            .iter()
            .position(|l| l.contains("/credentials/oidc"))
            .unwrap()
            > put
    );
    assert_eq!(
        kratos[0].uri,
        format!("/admin/identities/{ID}?include_credential=oidc"),
        "the links are read from the identity first"
    );
    // Kratos' credential DELETE refuses passkeys; a JSON patch removes them.
    let patches: Vec<_> = kratos.iter().filter(|c| c.method == "PATCH").collect();
    assert_eq!(patches.len(), 1, "an absent passkey is not patched again");
    let patch = patches[0];
    assert_eq!(patch.path(), format!("/admin/identities/{ID}"));
    assert_eq!(
        patch.body,
        json!([{"op": "remove", "path": "/credentials/passkey"}])
    );
}

#[tokio::test]
async fn each_recovery_replaces_the_password_with_a_different_one() {
    let first = harness(&[]).await;
    let second = harness(&[]).await;

    first.post("/kratos/after-recovery", recovery()).await;
    second.post("/kratos/after-recovery", recovery()).await;

    let password = |h: &Harness| {
        h.log
            .of("kratos")
            .iter()
            .find(|c| c.method == "PUT")
            .unwrap()
            .body["credentials"]["password"]["config"]["password"]
            .clone()
    };
    assert_ne!(password(&first), password(&second));
}

#[tokio::test]
async fn credentials_are_purged_before_sessions_and_tokens_are_revoked_in_the_documented_order() {
    let harness = harness(&[SESSION, OTHER, OTHER_2]).await;

    let (status, _) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::OK);
    let lines = harness.log.lines();
    let is_credential = |l: &String| {
        l.contains("/credentials/") || l.starts_with("kratos PUT") || l.starts_with("kratos PATCH")
    };
    let is_session = |l: &String| l.contains("/sessions") || l.contains("/admin/sessions/");
    let first_credential = lines.iter().position(is_credential).unwrap();
    let first_session = lines.iter().position(is_session).unwrap();
    assert!(first_credential < first_session, "{lines:#?}");
    let revocations: Vec<&String> = lines
        .iter()
        .filter(|l| {
            !l.contains("/credentials/")
                && !l.starts_with("kratos PUT")
                && !l.starts_with("kratos PATCH")
                && !l.starts_with("kratos GET")
        })
        .collect();
    assert_eq!(
        revocations[..2],
        [
            &format!("kratos DELETE /admin/sessions/{OTHER}"),
            &format!("kratos DELETE /admin/sessions/{OTHER_2}"),
        ]
    );
    let mut upstream_revocations: Vec<&String> = revocations[2..].to_vec();
    upstream_revocations.sort();
    assert_eq!(
        upstream_revocations,
        [
            &"bff POST /internal/revoke".to_string(),
            &format!("hydra DELETE /admin/oauth2/auth/sessions/consent?subject={ID}&all=true"),
            &format!("hydra DELETE /admin/oauth2/auth/sessions/login?subject={ID}"),
        ]
    );
}

#[tokio::test]
async fn credentials_are_purged_again_after_the_sessions_end() {
    let harness = harness(&[SESSION, OTHER]).await;

    harness.post("/kratos/after-recovery", recovery()).await;

    let lines = harness.log.lines();
    let first_session = lines
        .iter()
        .position(|l| l.contains("/admin/sessions/"))
        .unwrap();
    let last_credential = lines
        .iter()
        .rposition(|l| l.contains("/credentials/") || l.starts_with("kratos PATCH"))
        .unwrap();
    assert!(first_session < last_credential, "{lines:#?}");
    let puts = lines.iter().filter(|l| l.starts_with("kratos PUT")).count();
    assert_eq!(puts, 2, "{lines:#?}");
}

#[tokio::test]
async fn one_session_that_wont_end_does_not_stop_the_others_being_revoked() {
    let sessions = Arc::new(Mutex::new(vec![OTHER.to_string(), OTHER_2.to_string()]));
    let harness = Harness::with(
        {
            let sessions = sessions.clone();
            move |call: &Call| match (call.method.as_str(), call.path()) {
                ("GET", path) if path.ends_with("/sessions") => (
                    200,
                    Value::Array(
                        sessions
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|id| json!({"id": id}))
                            .collect(),
                    ),
                ),
                ("GET", _) => (200, identity_json(ID, "a@example.com", true)),
                ("DELETE", path) if path.ends_with(OTHER) => (500, json!({})),
                ("DELETE", path) if path.starts_with("/admin/sessions/") => {
                    sessions
                        .lock()
                        .unwrap()
                        .retain(|s| !path.ends_with(s.as_str()));
                    (204, Value::Null)
                }
                _ => (204, Value::Null),
            }
        },
        support::no_content,
        support::no_content,
    )
    .await;

    let (status, _) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        harness
            .log
            .lines()
            .contains(&format!("kratos DELETE /admin/sessions/{OTHER_2}"))
    );
}

#[tokio::test]
async fn an_identity_deactivated_meanwhile_is_not_written_back_active() {
    let gets = Arc::new(Mutex::new(0));
    let harness = Harness::with(
        move |call: &Call| match call.method.as_str() {
            "GET" if call.path().ends_with("/sessions") => (200, json!([])),
            "GET" => {
                let mut n = gets.lock().unwrap();
                *n += 1;
                let mut identity = identity_json(ID, "a@example.com", true);
                if *n > 1 {
                    identity["state"] = "inactive".into();
                }
                (200, identity)
            }
            _ => (204, Value::Null),
        },
        support::no_content,
        support::no_content,
    )
    .await;

    let (status, _) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        !harness
            .log
            .lines()
            .iter()
            .any(|l| l.starts_with("kratos PUT")),
        "{:#?}",
        harness.log.lines()
    );
}

#[tokio::test]
async fn the_recovery_session_itself_survives_and_other_sessions_do_not() {
    let harness = harness(&[OTHER, SESSION]).await;

    harness.post("/kratos/after-recovery", recovery()).await;

    let revoked: Vec<String> = harness
        .log
        .lines()
        .into_iter()
        .filter(|l| l.starts_with("kratos DELETE /admin/sessions/"))
        .collect();
    assert_eq!(revoked, [format!("kratos DELETE /admin/sessions/{OTHER}")]);
    assert!(
        !harness
            .log
            .lines()
            .iter()
            .any(|l| l.contains(&format!("/sessions/{SESSION}")))
    );
}

#[tokio::test]
async fn without_a_session_id_every_kratos_session_is_revoked() {
    let harness = harness(&[]).await;

    let (status, _) = harness
        .post("/kratos/after-recovery", json!({"identity_id": ID}))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        harness
            .log
            .lines()
            .contains(&format!("kratos DELETE /admin/identities/{ID}/sessions"))
    );
}

#[tokio::test]
async fn bff_is_told_with_the_bff_key_and_the_identity_id() {
    let harness = harness(&[]).await;

    harness.post("/kratos/after-recovery", recovery()).await;

    let bff = harness.log.of("bff");
    assert_eq!(bff.len(), 1);
    assert_eq!(
        bff[0].authorization.as_deref(),
        Some(&*format!("Bearer {}", support::BFF_KEY))
    );
    assert_eq!(bff[0].body, json!({"sub": ID}));
}

#[tokio::test]
async fn a_credential_the_identity_does_not_have_is_not_an_error() {
    let harness = Harness::with(
        |call| {
            if call.path().contains("/credentials/") {
                (404, json!({}))
            } else if call.method == "GET" {
                (200, identity_json(ID, "a@example.com", true))
            } else {
                (204, Value::Null)
            }
        },
        support::no_content,
        support::no_content,
    )
    .await;

    let (status, _) = harness
        .post("/kratos/after-recovery", json!({"identity_id": ID}))
        .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_failed_step_fails_the_hook_but_every_other_step_still_runs() {
    type Responder = fn(&Call) -> (u16, Value);
    let ok_kratos: Responder = |call| match call.method.as_str() {
        "GET" => (200, identity_json(ID, "a@example.com", true)),
        _ => (204, Value::Null),
    };
    let cases: [(&str, Responder, Responder, Responder); 5] = [
        (
            "kratos oidc delete",
            |call| {
                if call.path().ends_with("/oidc") {
                    (500, json!({}))
                } else if call.method == "GET" {
                    (200, identity_with_social_logins())
                } else {
                    (204, Value::Null)
                }
            },
            support::no_content,
            support::no_content,
        ),
        (
            "kratos credential delete",
            |call| {
                if call.path().ends_with("/totp") {
                    (500, json!({}))
                } else if call.method == "GET" {
                    (200, identity_json(ID, "a@example.com", true))
                } else {
                    (204, Value::Null)
                }
            },
            support::no_content,
            support::no_content,
        ),
        (
            "kratos session revoke",
            |call| {
                if call.path().ends_with("/sessions") && call.method == "DELETE" {
                    (500, json!({}))
                } else if call.method == "GET" {
                    (200, identity_json(ID, "a@example.com", true))
                } else {
                    (204, Value::Null)
                }
            },
            support::no_content,
            support::no_content,
        ),
        (
            "hydra consent",
            ok_kratos,
            |call| {
                if call.uri.contains("/consent") {
                    (500, json!({}))
                } else {
                    (204, Value::Null)
                }
            },
            support::no_content,
        ),
        ("bff", ok_kratos, support::no_content, |_| {
            (500, json!({"error": "boom"}))
        }),
    ];
    for (what, kratos, hydra, bff) in cases {
        let harness = Harness::with(kratos, hydra, bff).await;

        let (status, body) = harness
            .post("/kratos/after-recovery", json!({"identity_id": ID}))
            .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY, "{what}");
        assert_eq!(body["reason"], "RevocationIncomplete", "{what}");
        assert_eq!(
            harness.log.of("hydra").len(),
            2,
            "{what}: hydra still revoked"
        );
        assert_eq!(harness.log.of("bff").len(), 1, "{what}: bff still told");
        assert!(!body.to_string().contains("boom"), "{what}");
    }
}

#[tokio::test]
async fn an_unreachable_upstream_fails_the_hook() {
    let mut harness = harness(&[]).await;
    harness.config.bff_internal_url = "http://127.0.0.1:1".to_string();

    let (status, _) = harness
        .post("/kratos/after-recovery", json!({"identity_id": ID}))
        .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn an_identity_id_that_is_not_a_uuid_is_refused_without_any_call() {
    let harness = harness(&[]).await;

    for body in [
        json!({"identity_id": "../x"}),
        json!({"identity_id": ID, "session_id": "nope"}),
        json!({}),
    ] {
        let (status, _) = harness.post("/kratos/after-recovery", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(harness.log.calls().is_empty());
}

#[tokio::test]
async fn a_password_change_revokes_like_recovery_but_leaves_the_credentials_alone() {
    let harness = harness(&[SESSION, OTHER]).await;

    let (status, _) = harness
        .post("/kratos/after-password-change", recovery())
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        harness
            .log
            .lines()
            .into_iter()
            .filter(|l| !l.starts_with("kratos GET"))
            .collect::<Vec<_>>(),
        [
            format!("kratos DELETE /admin/sessions/{OTHER}"),
            format!("hydra DELETE /admin/oauth2/auth/sessions/consent?subject={ID}&all=true"),
            format!("hydra DELETE /admin/oauth2/auth/sessions/login?subject={ID}"),
            "bff POST /internal/revoke".to_string(),
        ]
    );
    assert!(harness.log.of("kratos").iter().all(|c| c.method != "PUT"));
}

#[tokio::test]
async fn an_identity_without_social_logins_has_no_oidc_credential_deleted() {
    let harness = Harness::new().await;

    let (status, _) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!credential_deletes(&harness).contains(&"oidc".to_string()));
}

#[tokio::test]
async fn a_kratos_that_hangs_does_not_stop_hydra_and_bff_being_told() {
    let mut harness = harness(&[]).await;
    harness.config.request_timeout_secs = 4;
    harness.config.upstream_timeout_secs = 30;
    harness.config.kratos_admin_url = support::hanging_server().await;

    let started = std::time::Instant::now();
    let (status, body) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "RevocationIncomplete");
    assert_eq!(harness.log.of("hydra").len(), 2, "hydra still revoked");
    assert_eq!(harness.log.of("bff").len(), 1, "bff still told");
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}

#[tokio::test]
async fn a_hydra_that_hangs_does_not_stop_bff_being_told() {
    let mut harness = harness(&[]).await;
    harness.config.request_timeout_secs = 4;
    harness.config.upstream_timeout_secs = 30;
    harness.config.hydra_admin_url = support::hanging_server().await;

    let started = std::time::Instant::now();
    let (status, body) = harness.post("/kratos/after-recovery", recovery()).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "RevocationIncomplete");
    assert_eq!(harness.log.of("bff").len(), 1, "bff still told");
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}
