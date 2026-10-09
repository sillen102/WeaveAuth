//! Login translates Kratos' texts by their numeric id. This drives the real Kratos (the pinned
//! image) and fails when an id stops meaning what login thinks it means, which is what a Kratos
//! upgrade that renumbers or rewords a message looks like.
//!
//! Every id login translates (`weaveauth_login::translated_ids`) is either in [`PINNED`], whose
//! id and English wording are checked against what the exercised flows show, or in
//! [`NOT_OBSERVABLE`] with the reason no flow here can show it. A new translation therefore fails
//! until it is put in one of them. A failure is a reminder to update the ids in
//! `login/src/i18n.rs` and the texts in `templates/locales/en.json`.
//!
//! The tables and the test that checks them need no Docker; the tests against Kratos do. The
//! `{placeholder}` names (`weaveauth_login::context_names`) are checked against what Kratos sends.

use std::collections::HashSet;
use weaveauth_login::translated_ids;

/// What Kratos says for an id login translates: where it sits, its id, the key login files it
/// under, and how Kratos' own (English) text starts.
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
struct Pinned {
    place: &'static str,
    id: u64,
    key: &'static str,
    starts_with: &'static str,
}

const fn label(id: u64, key: &'static str, starts_with: &'static str) -> Pinned {
    Pinned {
        place: "label",
        id,
        key,
        starts_with,
    }
}

const fn message(id: u64, key: &'static str, starts_with: &'static str) -> Pinned {
    Pinned {
        place: "message",
        id,
        key,
        starts_with,
    }
}

const PINNED: &[Pinned] = &[
    message(
        1_050_001,
        "InfoSelfServiceSettingsUpdateSuccess",
        "Your changes have been saved",
    ),
    message(
        1_060_001,
        "InfoSelfServiceRecoverySuccessful",
        "You successfully recovered your account",
    ),
    message(
        1_080_002,
        "InfoSelfServiceVerificationSuccessful",
        "You successfully verified",
    ),
    message(
        4_000_007,
        "ErrorValidationDuplicateCredentials",
        "An account with the same identifier",
    ),
    label(1_010_002, "InfoSelfServiceLoginWith", "Sign in with "),
    label(
        1_010_021,
        "InfoSelfServiceLoginPasskey",
        "Sign in with passkey",
    ),
    label(
        1_010_022,
        "InfoSelfServiceLoginPassword",
        "Sign in with password",
    ),
    label(1_040_001, "InfoSelfServiceRegistration", "Sign up"),
    label(
        1_040_002,
        "InfoSelfServiceRegistrationWith",
        "Sign up with ",
    ),
    label(
        1_040_007,
        "InfoSelfServiceRegistrationRegisterPasskey",
        "Sign up with passkey",
    ),
    label(1_040_008, "InfoSelfServiceRegistrationBack", "Back"),
    label(1_050_002, "InfoSelfServiceSettingsUpdateLinkOidc", "Link "),
    label(
        1_050_019,
        "InfoSelfServiceSettingsRegisterPasskey",
        "Add passkey",
    ),
    label(1_070_001, "InfoNodeLabelInputPassword", "Password"),
    label(1_070_003, "InfoNodeLabelSave", "Save"),
    label(1_070_007, "InfoNodeLabelEmail", "Email"),
    label(1_070_008, "InfoNodeLabelResendOTP", "Resend code"),
    label(1_070_009, "InfoNodeLabelContinue", "Continue"),
    label(1_070_010, "InfoNodeLabelRecoveryCode", "Recovery code"),
    label(
        1_070_011,
        "InfoNodeLabelVerificationCode",
        "Verification code",
    ),
    message(
        1_060_003,
        "InfoSelfServiceRecoveryEmailWithCodeSent",
        "An email containing a recovery code",
    ),
    message(
        1_080_003,
        "InfoSelfServiceVerificationEmailWithCodeSent",
        "An email containing a verification code",
    ),
    message(4_000_002, "ErrorValidationRequired", "Property "),
    message(
        4_000_006,
        "ErrorValidationInvalidCredentials",
        "The provided credentials are invalid",
    ),
    message(
        4_000_032,
        "ErrorValidationPasswordMinLength",
        "The password must be at least ",
    ),
    message(
        4_000_040,
        "ErrorValidationEmail",
        "Enter a valid email address",
    ),
];

/// Keys login translates that no flow here shows, by the reason. They are what a deployer's
/// Kratos may still send, so they stay translated.
const NOT_OBSERVABLE: &[(&str, &[&str])] = &[
    (
        "a value the identity schema or the password policy here does not constrain, so no scripted submission provokes it",
        &[
            "ErrorValidationConst",
            "ErrorValidationConstGeneric",
            "ErrorValidationExclusiveMaximum",
            "ErrorValidationExclusiveMinimum",
            "ErrorValidationGeneric",
            "ErrorValidationIdentifierMissing",
            "ErrorValidationInvalidFormat",
            "ErrorValidationMaxItems",
            "ErrorValidationMaxLength",
            "ErrorValidationMaximum",
            "ErrorValidationMinItems",
            "ErrorValidationMinLength",
            "ErrorValidationMinimum",
            "ErrorValidationMultipleOf",
            "ErrorValidationPasswordIdentifierTooSimilar",
            "ErrorValidationPasswordMaxLength",
            "ErrorValidationPasswordNewSameAsOld",
            "ErrorValidationPasswordPolicyViolationGeneric",
            "ErrorValidationPasswordTooManyBreaches",
            "ErrorValidationPhone",
            "ErrorValidationUniqueItems",
            "ErrorValidationWrongType",
        ],
    ),
    (
        "an expired, retried or broken-state flow, or a request no scripted flow can make, which fresh flows never reach",
        &[
            "ErrorSystemGeneric",
            "ErrorSystemNoAuthenticationMethodsAvailable",
            "ErrorValidationAccountNotFound",
            "ErrorValidationAddressNotVerified",
            "ErrorValidationLoginFlowExpired",
            "ErrorValidationLoginNoStrategyFound",
            "ErrorValidationLoginRetrySuccess",
            "ErrorValidationRecoveryFlowExpired",
            "ErrorValidationRecoveryMissingRecoveryToken",
            "ErrorValidationRecoveryNoStrategyFound",
            "ErrorValidationRecoveryRetrySuccess",
            "ErrorValidationRecoveryStateFailure",
            "ErrorValidationRecoveryTokenInvalidOrAlreadyUsed",
            "ErrorValidationRegistrationFlowExpired",
            "ErrorValidationRegistrationNoStrategyFound",
            "ErrorValidationRegistrationRetrySuccess",
            "ErrorValidationSettingsFlowExpired",
            "ErrorValidationSettingsNoStrategyFound",
            "ErrorValidationTraitsMismatch",
            "ErrorValidationVerificationFlowExpired",
            "ErrorValidationVerificationMissingVerificationToken",
            "ErrorValidationVerificationNoStrategyFound",
            "ErrorValidationVerificationRetrySuccess",
            "ErrorValidationVerificationStateFailure",
            "ErrorValidationVerificationTokenInvalidOrAlreadyUsed",
        ],
    ),
    (
        "the sign-in or sign-up code method, or a recovery or verification variant this stack does not use",
        &[
            "ErrorValidationLoginCodeInvalidOrAlreadyUsed",
            "ErrorValidationNoCodeUser",
            "ErrorValidationRecoveryCodeInvalidOrAlreadyUsed",
            "ErrorValidationRegistrationCodeInvalidOrAlreadyUsed",
            "ErrorValidationVerificationCodeInvalidOrAlreadyUsed",
            "InfoNodeLabelLoginCode",
            "InfoNodeLabelRecoveryAddress",
            "InfoNodeLabelRegistrationCode",
            "InfoNodeLabelVerifyOTP",
            "InfoSelfServiceLoginAAL2CodeAddress",
            "InfoSelfServiceLoginCode",
            "InfoSelfServiceLoginCodeMFA",
            "InfoSelfServiceLoginCodeMFAHint",
            "InfoSelfServiceLoginCodeSent",
            "InfoSelfServiceRecoveryAskForFullAddress",
            "InfoSelfServiceRecoveryAskToChooseAddress",
            "InfoSelfServiceRecoveryBack",
            "InfoSelfServiceRecoveryEmailSent",
            "InfoSelfServiceRecoveryMessageMaskedWithCodeSent",
            "InfoSelfServiceRegistrationEmailWithCodeSent",
            "InfoSelfServiceRegistrationRegisterCode",
            "InfoSelfServiceVerificationEmailSent",
        ],
    ),
    (
        "a second factor, security key or captcha, which the scripted visitors have not set up",
        &[
            "ErrorValidationCaptchaError",
            "ErrorValidationLookupAlreadyUsed",
            "ErrorValidationLookupInvalid",
            "ErrorValidationNoLookup",
            "ErrorValidationNoTOTPDevice",
            "ErrorValidationNoWebAuthnDevice",
            "ErrorValidationSuchNoWebAuthnUser",
            "ErrorValidationTOTPVerifierWrong",
            "InfoLoginLookup",
            "InfoLoginLookupLabel",
            "InfoLoginTOTP",
            "InfoNodeLabelCaptcha",
            "InfoSelfServiceLoginContinueWebAuthn",
            "InfoSelfServiceLoginMFA",
            "InfoSelfServiceLoginReAuth",
            "InfoSelfServiceLoginTOTPLabel",
            "InfoSelfServiceLoginVerify",
            "InfoSelfServiceLoginWebAuthn",
            "InfoSelfServiceLoginWebAuthnPasswordless",
            "InfoSelfServiceRegistrationRegisterWebAuthn",
            "InfoSelfServiceSettingsDisableLookup",
            "InfoSelfServiceSettingsLookupConfirm",
            "InfoSelfServiceSettingsLookupSecretLabel",
            "InfoSelfServiceSettingsRegenerateLookup",
            "InfoSelfServiceSettingsRegisterWebAuthn",
            "InfoSelfServiceSettingsRegisterWebAuthnDisplayName",
            "InfoSelfServiceSettingsRemoveWebAuthn",
            "InfoSelfServiceSettingsRevealLookup",
            "InfoSelfServiceSettingsTOTPQRCode",
            "InfoSelfServiceSettingsTOTPSecretLabel",
            "InfoSelfServiceSettingsUpdateUnlinkTOTP",
        ],
    ),
    (
        "a social sign-in that collides with an existing account",
        &[
            "ErrorValidationDuplicateCredentialsOnOIDCLink",
            "ErrorValidationDuplicateCredentialsWithHints",
            "ErrorValidationLoginAddressUnknown",
            "ErrorValidationLoginLinkedCredentialsDoNotMatch",
            "InfoNodeLabelLoginAndLinkCredential",
            "InfoSelfServiceLoginAndLink",
            "InfoSelfServiceLoginLink",
            "InfoSelfServiceLoginWithAndLink",
        ],
    ),
    (
        "covered by the system test google_sign_up_missing_a_trait_can_be_completed_on_the_form, \
         which login's `continuing` depends on",
        &["InfoSelfServiceRegistrationContinue"],
    ),
    (
        "Kratos sends another id for that screen here: the identifier and the phone number are \
         generated title labels, and the sign-in button is `Sign in with password`",
        &[
            "InfoNodeLabelID",
            "InfoNodeLabelPhoneNumber",
            "InfoSelfServiceLogin",
        ],
    ),
    (
        "a button the enabled methods do not send",
        &["InfoNodeLabelSubmit", "InfoSelfServiceLoginContinue"],
    ),
    (
        "a screen the scripted visitors do not reach: it needs a passkey or a linked social \
         sign-in on the account, or a registration offering several methods",
        &[
            "InfoSelfServiceRegistrationChooseCredentials",
            "InfoSelfServiceSettingsRemovePasskey",
            "InfoSelfServiceSettingsUpdateUnlinkOidc",
        ],
    ),
];

#[test]
fn every_translated_id_is_pinned_or_excused_and_nothing_stale_is_listed() {
    let translated = translated_ids();
    let keys: HashSet<&str> = translated.iter().map(|(_, _, key)| *key).collect();
    let pinned: HashSet<&str> = PINNED.iter().map(|p| p.key).collect();
    let excused: Vec<&str> = NOT_OBSERVABLE
        .iter()
        .flat_map(|(_, keys)| keys.iter().copied())
        .collect();

    let mut uncovered: Vec<&&str> = keys
        .iter()
        .filter(|key| !pinned.contains(**key) && !excused.contains(key))
        .collect();
    uncovered.sort();
    assert!(
        uncovered.is_empty(),
        "login translates these but they are neither in PINNED nor in NOT_OBSERVABLE: {uncovered:#?}"
    );
    let stale: Vec<&&str> = pinned
        .iter()
        .chain(excused.iter())
        .filter(|key| !keys.contains(**key))
        .collect();
    assert!(
        stale.is_empty(),
        "no longer translated by login: {stale:#?}"
    );
    let both: Vec<&&str> = excused
        .iter()
        .filter(|key| pinned.contains(**key))
        .collect();
    assert!(both.is_empty(), "pinned and excused: {both:#?}");
    assert_eq!(
        excused.len(),
        excused.iter().collect::<HashSet<_>>().len(),
        "a key is excused twice"
    );
}

#[cfg(feature = "docker")]
mod against_kratos {
    use super::*;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use tokio::sync::OnceCell;
    use weaveauth_login::context_names;
    use weaveauth_system_tests::support::browser::Follow;
    use weaveauth_system_tests::support::flows::*;
    use weaveauth_system_tests::support::{Options, Stack, shared};

    /// Kratos' label for a trait; login looks it up by the trait's path instead of its id.
    const GENERATED_LABEL_ID: u64 = 1_070_002;

    async fn stack() -> &'static Stack {
        shared(Options::default()).await
    }

    /// What the scripted flows showed, collected once for every test of this file.
    async fn seen() -> &'static Seen {
        static SEEN: OnceCell<Seen> = OnceCell::const_new();
        SEEN.get_or_init(|| async { observed(stack().await).await })
            .await
    }

    /// One text a flow showed: (place, id, text) and the `context` Kratos sent with it.
    type Seen = BTreeSet<(&'static str, u64, String, String)>;

    /// Every text of a flow: its messages, its nodes' messages and labels, and its links' titles.
    fn collect(flow: &Value, into: &mut Seen) {
        let mut take = |place: &'static str, text: &Value| {
            if let Some(id) = text["id"].as_u64() {
                let shown = text["text"].as_str().unwrap_or_default().to_string();
                into.insert((place, id, shown, text["context"].to_string()));
            }
        };
        for text in flow["ui"]["messages"].as_array().into_iter().flatten() {
            take("message", text);
        }
        for node in flow["ui"]["nodes"].as_array().into_iter().flatten() {
            for text in node["messages"].as_array().into_iter().flatten() {
                take("message", text);
            }
            take("label", &node["meta"]["label"]);
            take("label", &node["attributes"]["title"]);
        }
    }

    fn id_of(flow: &Value) -> &str {
        flow["id"].as_str().expect("flow id")
    }

    /// Starts the flows login renders, makes each answer with the messages a user hits, and collects
    /// every text Kratos showed along the way.
    async fn observed(stack: &Stack) -> Seen {
        let mut seen = Seen::new();
        let b = stack.browser();

        // Login: the buttons, then a wrong password.
        let page = bff_login(stack, &b).await;
        let login = flow_of(stack, &b, "login", &page).await;
        collect(&login, &mut seen);
        let challenge = login["oauth2_login_challenge"].as_str().expect("challenge");
        let wrong = [
            ("identifier", "nobody@example.test"),
            ("password", "wrong-password"),
        ];
        submit(&b, &login, "password", &wrong, Follow::No).await;
        collect(&flow(stack, &b, "login", id_of(&login)).await, &mut seen);

        // Registration: a malformed email and a missing trait, then a password that is too short.
        let registration = new_flow(stack, &b, "registration", Some(challenge)).await;
        collect(&registration, &mut seen);
        let invalid = [("traits.email", "not-an-email"), ("traits.first_name", "A")];
        submit(&b, &registration, "profile", &invalid, Follow::No).await;
        collect(
            &flow(stack, &b, "registration", id_of(&registration)).await,
            &mut seen,
        );

        let email = unique_email("ids");
        let registration = new_flow(stack, &b, "registration", Some(challenge)).await;
        let traits = [
            ("traits.email", email.as_str()),
            ("traits.first_name", "Ids"),
            ("traits.last_name", "Test"),
            ("traits.phone_number", "+46701234567"),
        ];
        submit(&b, &registration, "profile", &traits, Follow::No).await;
        let registration = flow(stack, &b, "registration", id_of(&registration)).await;
        submit(
            &b,
            &registration,
            "password",
            &[("password", "x")],
            Follow::No,
        )
        .await;
        collect(
            &flow(stack, &b, "registration", id_of(&registration)).await,
            &mut seen,
        );

        // Recovery and verification: the page, then the answer to a known address.
        let known = unique_email("known");
        let password = json!({"password": {"config": {"password": PASSWORD}}});
        stack.create_identity(&known, true, password).await;
        for kind in ["recovery", "verification"] {
            let b = stack.browser();
            let started = new_flow(stack, &b, kind, None).await;
            collect(&started, &mut seen);
            submit(
                &b,
                &started,
                "code",
                &[("email", known.as_str())],
                Follow::No,
            )
            .await;
            collect(&flow(stack, &b, kind, id_of(&started)).await, &mut seen);
        }

        // Settings: what a signed-in user can change, and the answer to a change.
        let signed_in = session_for(stack, &known, PASSWORD).await;
        let settings = new_flow(stack, &signed_in, "settings", None).await;
        collect(&settings, &mut seen);
        let renamed = [("traits.first_name", "Changed")];
        submit(&signed_in, &settings, "profile", &renamed, Follow::No).await;
        collect(
            &flow(stack, &signed_in, "settings", id_of(&settings)).await,
            &mut seen,
        );

        // Recovery to the end, for an address of its own (its mail is the only one): the settings
        // flow Kratos opens afterwards carries its own message.
        let recovering = unique_email("recovering");
        let password = json!({"password": {"config": {"password": PASSWORD}}});
        stack.create_identity(&recovering, true, password).await;
        let b = stack.browser();
        let started = new_flow(stack, &b, "recovery", None).await;
        submit(
            &b,
            &started,
            "code",
            &[("email", recovering.as_str())],
            Follow::No,
        )
        .await;
        let code = mail_code(stack, &recovering, "Reset your password", 1).await;
        let recovery = flow(stack, &b, "recovery", id_of(&started)).await;
        let done = submit(
            &b,
            &recovery,
            "code",
            &[("code", code.as_str())],
            Follow::No,
        )
        .await;
        let target = done.redirect_target().expect("recovery redirect");
        let settings_id = target
            .query_pairs()
            .find(|(name, _)| name == "flow")
            .map(|(_, id)| id.to_string())
            .expect("the settings flow id");
        collect(&flow(stack, &b, "settings", &settings_id).await, &mut seen);

        // Verification to the end, for an address that is not verified yet.
        let unverified = unique_email("unverified");
        let password = json!({"password": {"config": {"password": PASSWORD}}});
        stack.create_identity(&unverified, false, password).await;
        let b = stack.browser();
        let started = new_flow(stack, &b, "verification", None).await;
        let address = [("email", unverified.as_str())];
        submit(&b, &started, "code", &address, Follow::No).await;
        let code = mail_code(stack, &unverified, "verification code", 1).await;
        let verification = flow(stack, &b, "verification", id_of(&started)).await;
        submit(
            &b,
            &verification,
            "code",
            &[("code", code.as_str())],
            Follow::No,
        )
        .await;
        collect(
            &flow(stack, &b, "verification", id_of(&started)).await,
            &mut seen,
        );

        // Registering an address that is taken.
        let b = stack.browser();
        let page = bff_login(stack, &b).await;
        let login = flow_of(stack, &b, "login", &page).await;
        let challenge = login["oauth2_login_challenge"].as_str().expect("challenge");
        let registration = new_flow(stack, &b, "registration", Some(challenge)).await;
        let taken = [
            ("traits.email", known.as_str()),
            ("traits.first_name", "Taken"),
            ("traits.last_name", "Test"),
            ("traits.phone_number", "+46701234568"),
        ];
        submit(&b, &registration, "profile", &taken, Follow::No).await;
        let registration = flow(stack, &b, "registration", id_of(&registration)).await;
        let password = [("password", PASSWORD)];
        submit(&b, &registration, "password", &password, Follow::No).await;
        collect(
            &flow(stack, &b, "registration", id_of(&registration)).await,
            &mut seen,
        );
        seen
    }

    #[tokio::test]
    async fn the_ids_login_translates_still_mean_what_it_thinks() {
        let seen = seen().await;
        let translated = translated_ids();

        for pinned in PINNED {
            let shown: Vec<&String> = seen
                .iter()
                .filter(|(place, id, ..)| *place == pinned.place && *id == pinned.id)
                .map(|(_, _, text, _)| text)
                .collect();
            assert!(
                !shown.is_empty(),
                "Kratos no longer showed {} {} ({}): did it renumber it?",
                pinned.place,
                pinned.id,
                pinned.key
            );
            for text in shown {
                assert!(
                    text.starts_with(pinned.starts_with),
                    "{} {} ({}) now says {text:?}",
                    pinned.place,
                    pinned.id,
                    pinned.key
                );
            }
            assert!(
                translated.contains(&(pinned.place, pinned.id, pinned.key)),
                "login files {} {} elsewhere than {}",
                pinned.place,
                pinned.id,
                pinned.key
            );
        }
    }

    #[tokio::test]
    async fn kratos_still_sends_the_context_names_the_texts_fill_in() {
        let translated = translated_ids();

        for (place, id, _, context) in seen().await {
            let Some((_, key)) = translated
                .iter()
                .find(|(p, i, _)| p == place && i == id)
                .map(|(_, _, key)| ((), *key))
            else {
                continue;
            };
            let Some((_, names)) = context_names().iter().find(|(k, _)| *k == key) else {
                continue;
            };
            let context: Value = serde_json::from_str(context).expect("context");
            for name in *names {
                assert!(
                    context.get(name).is_some(),
                    "{key}: Kratos no longer sends {name:?} ({context})"
                );
            }
        }
    }

    #[tokio::test]
    async fn nothing_kratos_showed_is_translated_without_being_pinned() {
        let seen = seen().await;
        let translated = translated_ids();

        let unpinned: Vec<String> = seen
            .iter()
            .filter_map(|(place, id, text, _)| {
                let (_, _, key) = translated.iter().find(|(p, i, _)| p == place && i == id)?;
                let pinned = PINNED.iter().any(|p| p.place == *place && p.id == *id);
                (!pinned).then(|| format!("{place} {id} {key} ({text:?})"))
            })
            .collect();
        assert!(
            unpinned.is_empty(),
            "Kratos showed these translated texts, so PINNED must cover them (and NOT_OBSERVABLE must \
             not list them): {unpinned:#?}"
        );
    }

    #[tokio::test]
    async fn a_trait_label_is_still_the_generic_label_carrying_its_title() {
        let seen = seen().await;

        let traits: Vec<_> = seen
            .iter()
            .filter(|(place, id, ..)| *place == "label" && *id == GENERATED_LABEL_ID)
            .collect();
        assert!(
            !traits.is_empty(),
            "no generic trait label: did Kratos renumber it?"
        );
        for (_, _, text, context) in traits {
            let context: Value = serde_json::from_str(context).expect("context");
            assert_eq!(
                context["title"],
                json!(text),
                "the title is no longer the text"
            );
            assert!(
                context["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("traits.")),
                "the label no longer names its trait: {context}"
            );
        }
        assert!(
            translated_ids()
                .iter()
                .all(|(_, id, _)| *id != GENERATED_LABEL_ID),
            "the generic label is looked up by trait, not translated by id"
        );
    }

    #[tokio::test]
    async fn the_sign_in_identifier_is_a_generated_label_naming_its_trait() {
        let stack = stack().await;
        let b = stack.browser();
        let page = bff_login(stack, &b).await;
        let login = flow_of(stack, &b, "login", &page).await;

        let nodes = login["ui"]["nodes"].as_array().expect("nodes");
        let identifier = nodes
            .iter()
            .find(|node| node["attributes"]["name"] == "identifier")
            .expect("the identifier field");
        assert_eq!(identifier["meta"]["label"]["id"], GENERATED_LABEL_ID);
        assert_eq!(
            identifier["meta"]["label"]["context"]["name"],
            "traits.email"
        );
    }
}
