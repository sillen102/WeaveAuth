//! What Kratos says, in the visitor's language.
//!
//! Kratos sends every message, button and field label as English text with a numeric id and a
//! `context` of values. Login keeps the ids it knows as enums ([`MessageId`], [`LabelId`]) and
//! looks the text up in a deployer-replaceable JSON file per language (`templates/locales`):
//!
//! ```json
//! { "messages": {"ErrorValidationInvalidCredentials": "Wrong email or password."},
//!   "labels":   {"InfoSelfServiceLoginWith": "Sign in with {provider}"},
//!   "fields":   {"traits.first_name": "First name"} }
//! ```
//!
//! A message login has no text for gets the `Unknown` text, never Kratos' wording: that can be
//! English, or carry what a crafted link put in it. A label it has no text for keeps Kratos' text,
//! since an English button beats a wrong one (`Unknown` is therefore not a label key).
//! In a text, `{name}` is a `context` value and `{{` and `}}` are literal braces.

use crate::kratos::UiText;
use axum::http::HeaderMap;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

/// Longest language tag worth matching (BCP 47 tags are far shorter), so a header can't make the
/// matching walk a huge one.
const MAX_TAG_LEN: usize = 35;

/// How many tags of an `Accept-Language` value, or `language` cookies, are looked at.
const MAX_LANGUAGE_TAGS: usize = 16;

/// Cookie holding the language a visitor chose elsewhere (an application on the same domain).
const LANGUAGE_COOKIE: &str = "language";

/// The `context` names Kratos v26.2.0 (the image pinned in `system-tests/src/support/stack.rs`)
/// sends with each message and label that may have a `{placeholder}`, from its
/// `text/message_*.go`. A locale file may only use these names for a key (none for a key not
/// listed): a name Kratos does not send makes login show the generic text. The system tests check
/// that Kratos still sends them; re-check the names on a Kratos bump.
const CONTEXT_NAMES: &[(&str, &[&str])] = &[
    (
        "InfoSelfServiceRecoveryMessageMaskedWithCodeSent",
        &["masked_address"],
    ),
    ("ErrorValidationMinLength", &["min_length", "actual_length"]),
    ("ErrorValidationMaxLength", &["max_length", "actual_length"]),
    (
        "ErrorValidationPasswordMinLength",
        &["min_length", "actual_length"],
    ),
    (
        "ErrorValidationPasswordMaxLength",
        &["max_length", "actual_length"],
    ),
    ("ErrorValidationMinimum", &["minimum", "actual"]),
    ("ErrorValidationExclusiveMinimum", &["minimum", "actual"]),
    ("ErrorValidationMaximum", &["maximum", "actual"]),
    ("ErrorValidationExclusiveMaximum", &["maximum", "actual"]),
    ("ErrorValidationMultipleOf", &["base", "actual"]),
    ("ErrorValidationMaxItems", &["max_items", "actual_items"]),
    ("ErrorValidationMinItems", &["min_items", "actual_items"]),
    ("InfoSelfServiceLoginWith", &["provider", "provider_id"]),
    ("InfoSelfServiceLoginWithAndLink", &["provider"]),
    (
        "InfoSelfServiceLoginAAL2CodeAddress",
        &["address", "channel"],
    ),
    (
        "InfoSelfServiceRegistrationWith",
        &["provider", "provider_id"],
    ),
    ("InfoSelfServiceSettingsUpdateLinkOidc", &["provider"]),
    ("InfoSelfServiceSettingsUpdateUnlinkOidc", &["provider"]),
    (
        "InfoSelfServiceSettingsRemoveWebAuthn",
        &["display_name", "added_at", "added_at_unix"],
    ),
    (
        "InfoSelfServiceSettingsRemovePasskey",
        &["display_name", "added_at", "added_at_unix"],
    ),
];

/// Kratos' label for a trait (`traits.first_name`): the text is the schema's English `title`, so
/// the lookup is on the field's name instead.
const GENERATED_LABEL_ID: u64 = 1_070_002;

/// One enum per kind of Kratos text, one variant per id login has a translation for, named as in
/// Kratos' `text/id.go`. Re-check the ids on a Kratos upgrade.
macro_rules! kratos_ids {
    ($name:ident { $($variant:ident = $id:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $name {
            $($variant,)*
            /// An id login has no translation for.
            Unknown,
        }

        impl $name {
            /// Every (Kratos id, key) login translates.
            pub(crate) const IDS: &[(u64, &'static str)] = &[$(($id, stringify!($variant)),)*];

            pub(crate) fn from_id(id: u64) -> Self {
                match id {
                    $($id => Self::$variant,)*
                    _ => Self::Unknown,
                }
            }

            /// The key in the translation files.
            pub(crate) fn key(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)*
                    Self::Unknown => "Unknown",
                }
            }
        }
    };
}

kratos_ids!(MessageId {
    InfoSelfServiceLoginReAuth = 1_010_003,
    InfoSelfServiceLoginMFA = 1_010_004,
    InfoSelfServiceLoginWebAuthnPasswordless = 1_010_012,
    InfoSelfServiceLoginCodeSent = 1_010_014,
    InfoSelfServiceLoginLink = 1_010_016,
    InfoSelfServiceLoginCodeMFA = 1_010_019,
    InfoSelfServiceLoginCodeMFAHint = 1_010_020,
    InfoSelfServiceRegistrationEmailWithCodeSent = 1_040_005,
    InfoSelfServiceRegistrationChooseCredentials = 1_040_009,
    InfoSelfServiceSettingsUpdateSuccess = 1_050_001,
    InfoSelfServiceRecoverySuccessful = 1_060_001,
    InfoSelfServiceRecoveryEmailSent = 1_060_002,
    InfoSelfServiceRecoveryEmailWithCodeSent = 1_060_003,
    InfoSelfServiceRecoveryMessageMaskedWithCodeSent = 1_060_004,
    InfoSelfServiceRecoveryAskForFullAddress = 1_060_005,
    InfoSelfServiceRecoveryAskToChooseAddress = 1_060_006,
    InfoSelfServiceVerificationEmailSent = 1_080_001,
    InfoSelfServiceVerificationSuccessful = 1_080_002,
    InfoSelfServiceVerificationEmailWithCodeSent = 1_080_003,
    ErrorValidationGeneric = 4_000_001,
    ErrorValidationRequired = 4_000_002,
    ErrorValidationMinLength = 4_000_003,
    ErrorValidationInvalidFormat = 4_000_004,
    ErrorValidationPasswordPolicyViolationGeneric = 4_000_005,
    ErrorValidationInvalidCredentials = 4_000_006,
    ErrorValidationDuplicateCredentials = 4_000_007,
    ErrorValidationTOTPVerifierWrong = 4_000_008,
    ErrorValidationIdentifierMissing = 4_000_009,
    ErrorValidationAddressNotVerified = 4_000_010,
    ErrorValidationNoTOTPDevice = 4_000_011,
    ErrorValidationLookupAlreadyUsed = 4_000_012,
    ErrorValidationNoWebAuthnDevice = 4_000_013,
    ErrorValidationNoLookup = 4_000_014,
    ErrorValidationSuchNoWebAuthnUser = 4_000_015,
    ErrorValidationLookupInvalid = 4_000_016,
    ErrorValidationMaxLength = 4_000_017,
    ErrorValidationMinimum = 4_000_018,
    ErrorValidationExclusiveMinimum = 4_000_019,
    ErrorValidationMaximum = 4_000_020,
    ErrorValidationExclusiveMaximum = 4_000_021,
    ErrorValidationMultipleOf = 4_000_022,
    ErrorValidationMaxItems = 4_000_023,
    ErrorValidationMinItems = 4_000_024,
    ErrorValidationUniqueItems = 4_000_025,
    ErrorValidationWrongType = 4_000_026,
    ErrorValidationDuplicateCredentialsOnOIDCLink = 4_000_027,
    ErrorValidationDuplicateCredentialsWithHints = 4_000_028,
    ErrorValidationConst = 4_000_029,
    ErrorValidationConstGeneric = 4_000_030,
    ErrorValidationPasswordIdentifierTooSimilar = 4_000_031,
    ErrorValidationPasswordMinLength = 4_000_032,
    ErrorValidationPasswordMaxLength = 4_000_033,
    ErrorValidationPasswordTooManyBreaches = 4_000_034,
    ErrorValidationNoCodeUser = 4_000_035,
    ErrorValidationTraitsMismatch = 4_000_036,
    ErrorValidationAccountNotFound = 4_000_037,
    ErrorValidationCaptchaError = 4_000_038,
    ErrorValidationPasswordNewSameAsOld = 4_000_039,
    ErrorValidationEmail = 4_000_040,
    ErrorValidationPhone = 4_000_041,
    ErrorValidationLoginFlowExpired = 4_010_001,
    ErrorValidationLoginNoStrategyFound = 4_010_002,
    ErrorValidationRegistrationNoStrategyFound = 4_010_003,
    ErrorValidationSettingsNoStrategyFound = 4_010_004,
    ErrorValidationRecoveryNoStrategyFound = 4_010_005,
    ErrorValidationVerificationNoStrategyFound = 4_010_006,
    ErrorValidationLoginRetrySuccess = 4_010_007,
    ErrorValidationLoginCodeInvalidOrAlreadyUsed = 4_010_008,
    ErrorValidationLoginLinkedCredentialsDoNotMatch = 4_010_009,
    ErrorValidationLoginAddressUnknown = 4_010_010,
    ErrorValidationRegistrationFlowExpired = 4_040_001,
    ErrorValidationRegistrationRetrySuccess = 4_040_002,
    ErrorValidationRegistrationCodeInvalidOrAlreadyUsed = 4_040_003,
    ErrorValidationSettingsFlowExpired = 4_050_001,
    ErrorValidationRecoveryRetrySuccess = 4_060_001,
    ErrorValidationRecoveryStateFailure = 4_060_002,
    ErrorValidationRecoveryMissingRecoveryToken = 4_060_003,
    ErrorValidationRecoveryTokenInvalidOrAlreadyUsed = 4_060_004,
    ErrorValidationRecoveryFlowExpired = 4_060_005,
    ErrorValidationRecoveryCodeInvalidOrAlreadyUsed = 4_060_006,
    ErrorValidationVerificationTokenInvalidOrAlreadyUsed = 4_070_001,
    ErrorValidationVerificationRetrySuccess = 4_070_002,
    ErrorValidationVerificationStateFailure = 4_070_003,
    ErrorValidationVerificationMissingVerificationToken = 4_070_004,
    ErrorValidationVerificationFlowExpired = 4_070_005,
    ErrorValidationVerificationCodeInvalidOrAlreadyUsed = 4_070_006,
    ErrorSystemGeneric = 5_000_001,
    ErrorSystemNoAuthenticationMethodsAvailable = 5_000_002,
});

kratos_ids!(LabelId {
    InfoSelfServiceLogin = 1_010_001,
    InfoSelfServiceLoginWith = 1_010_002,
    InfoSelfServiceLoginVerify = 1_010_005,
    InfoSelfServiceLoginTOTPLabel = 1_010_006,
    InfoLoginLookupLabel = 1_010_007,
    InfoSelfServiceLoginWebAuthn = 1_010_008,
    InfoLoginTOTP = 1_010_009,
    InfoLoginLookup = 1_010_010,
    InfoSelfServiceLoginContinueWebAuthn = 1_010_011,
    InfoSelfServiceLoginContinue = 1_010_013,
    InfoSelfServiceLoginCode = 1_010_015,
    InfoSelfServiceLoginAndLink = 1_010_017,
    InfoSelfServiceLoginWithAndLink = 1_010_018,
    InfoSelfServiceLoginPasskey = 1_010_021,
    InfoSelfServiceLoginPassword = 1_010_022,
    InfoSelfServiceLoginAAL2CodeAddress = 1_010_023,
    InfoSelfServiceRegistration = 1_040_001,
    InfoSelfServiceRegistrationWith = 1_040_002,
    InfoSelfServiceRegistrationContinue = 1_040_003,
    InfoSelfServiceRegistrationRegisterWebAuthn = 1_040_004,
    InfoSelfServiceRegistrationRegisterCode = 1_040_006,
    InfoSelfServiceRegistrationRegisterPasskey = 1_040_007,
    InfoSelfServiceRegistrationBack = 1_040_008,
    InfoSelfServiceSettingsUpdateLinkOidc = 1_050_002,
    InfoSelfServiceSettingsUpdateUnlinkOidc = 1_050_003,
    InfoSelfServiceSettingsUpdateUnlinkTOTP = 1_050_004,
    InfoSelfServiceSettingsTOTPQRCode = 1_050_005,
    InfoSelfServiceSettingsRevealLookup = 1_050_007,
    InfoSelfServiceSettingsRegenerateLookup = 1_050_008,
    InfoSelfServiceSettingsLookupSecretLabel = 1_050_010,
    InfoSelfServiceSettingsLookupConfirm = 1_050_011,
    InfoSelfServiceSettingsRegisterWebAuthn = 1_050_012,
    InfoSelfServiceSettingsRegisterWebAuthnDisplayName = 1_050_013,
    InfoSelfServiceSettingsDisableLookup = 1_050_016,
    InfoSelfServiceSettingsTOTPSecretLabel = 1_050_017,
    InfoSelfServiceSettingsRemoveWebAuthn = 1_050_018,
    InfoSelfServiceSettingsRegisterPasskey = 1_050_019,
    InfoSelfServiceSettingsRemovePasskey = 1_050_020,
    InfoSelfServiceRecoveryBack = 1_060_007,
    InfoNodeLabelInputPassword = 1_070_001,
    InfoNodeLabelSave = 1_070_003,
    InfoNodeLabelID = 1_070_004,
    InfoNodeLabelSubmit = 1_070_005,
    InfoNodeLabelVerifyOTP = 1_070_006,
    InfoNodeLabelEmail = 1_070_007,
    InfoNodeLabelResendOTP = 1_070_008,
    InfoNodeLabelContinue = 1_070_009,
    InfoNodeLabelRecoveryCode = 1_070_010,
    InfoNodeLabelVerificationCode = 1_070_011,
    InfoNodeLabelRegistrationCode = 1_070_012,
    InfoNodeLabelLoginCode = 1_070_013,
    InfoNodeLabelLoginAndLinkCredential = 1_070_014,
    InfoNodeLabelCaptcha = 1_070_015,
    InfoNodeLabelRecoveryAddress = 1_070_016,
    InfoNodeLabelPhoneNumber = 1_070_017,
});

/// One language file. Every section is optional in a non-default language: what it lacks falls
/// back to the default language.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Locale {
    messages: HashMap<String, String>,
    labels: HashMap<String, String>,
    fields: HashMap<String, String>,
}

/// The loaded languages and the one every gap falls back to.
#[derive(Debug)]
pub(crate) struct Catalog {
    default: String,
    locales: HashMap<String, Locale>,
    /// Ids already logged as untranslated, so a busy page doesn't log them on every request.
    unmapped: Mutex<HashSet<(&'static str, u64)>>,
}

impl Catalog {
    /// Loads every `<tag>.json` in `dir` (`en.json`, `sv-se.json`; the tag is lowercased). A file
    /// that doesn't parse, or names a message or label login doesn't have, stops startup, and the
    /// default language must have a text for every message and label.
    pub(crate) fn load(dir: &Path, default: &str) -> anyhow::Result<Self> {
        let default = default.to_ascii_lowercase();
        let entries = std::fs::read_dir(dir).map_err(|error| {
            anyhow::anyhow!("cannot read the locales in {}: {error}", dir.display())
        })?;
        let mut locales = HashMap::new();
        for entry in entries {
            let path = entry
                .map_err(|error| {
                    anyhow::anyhow!("cannot list the locales in {}: {error}", dir.display())
                })?
                .path();
            let Some(tag) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            let tag = tag.to_ascii_lowercase();
            if tag.is_empty()
                || tag.len() > MAX_TAG_LEN
                || !tag
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                anyhow::bail!(
                    "{}: a locale tag is 1 to {MAX_TAG_LEN} letters, digits and `-`",
                    path.display()
                );
            }
            let raw = std::fs::read_to_string(&path)
                .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
            let locale: Locale = serde_json::from_str(&raw)
                .map_err(|error| anyhow::anyhow!("invalid locale {}: {error}", path.display()))?;
            locale.check_keys(&path)?;
            if locales.insert(tag.clone(), locale).is_some() {
                anyhow::bail!("two locale files for {tag:?} in {}", dir.display());
            }
        }
        let Some(fallback) = locales.get(&default) else {
            anyhow::bail!(
                "WA_DEFAULT_LOCALE is {default:?} but {} has no {default}.json",
                dir.display()
            );
        };
        fallback.check_complete(&default)?;
        Ok(Self {
            default,
            locales,
            unmapped: Mutex::default(),
        })
    }

    /// The language to answer in: the `language` cookie, else the best `Accept-Language` match,
    /// else the default. Each source counts only if it names a loaded language, so the result is
    /// safe to use as a key.
    pub(crate) fn negotiate(&self, headers: &HeaderMap) -> &str {
        language_cookies(headers)
            .take(MAX_LANGUAGE_TAGS)
            .find_map(|tag| self.matching(tag))
            .or_else(|| {
                let accepted = headers
                    .get(axum::http::header::ACCEPT_LANGUAGE)
                    .and_then(|value| value.to_str().ok())?;
                accepted_tags(accepted)
                    .iter()
                    .find_map(|tag| self.matching(tag))
            })
            .unwrap_or(&self.default)
    }

    pub(crate) fn translator<'a>(&'a self, language: &'a str) -> Translator<'a> {
        Translator {
            catalog: self,
            language,
        }
    }

    /// The loaded language for `tag` (`zh-Hant-TW`, or `zh_Hant_TW` as some frameworks write it),
    /// else for the tag with its last subtag dropped (`zh-hant`, then `zh`).
    fn matching(&self, tag: &str) -> Option<&str> {
        let tag = tag.trim();
        if tag.len() > MAX_TAG_LEN {
            return None;
        }
        let lowered = tag.to_ascii_lowercase().replace('_', "-");
        let mut rest = lowered.as_str();
        loop {
            if let Some((key, _)) = self.locales.get_key_value(rest) {
                return Some(key.as_str());
            }
            rest = rest.rsplit_once('-')?.0;
        }
    }

    /// Logs an id login has no translation for, the first time only.
    fn note_unmapped(&self, kind: &'static str, id: u64) {
        let first = self
            .unmapped
            .lock()
            .is_ok_and(|mut seen| seen.insert((kind, id)));
        if first {
            tracing::info!(id, kind, "no translation for a Kratos text");
        }
    }
}

impl Locale {
    fn check_keys(&self, path: &Path) -> anyhow::Result<()> {
        let known = |all: &[&'static str], section: &str, keys: &HashMap<String, String>| {
            let known: HashSet<&str> = all.iter().copied().collect();
            match keys.keys().find(|key| !known.contains(key.as_str())) {
                Some(key) => anyhow::bail!("{}: no {section} named {key:?}", path.display()),
                None => Ok(()),
            }
        };
        let messages: Vec<&str> = MessageId::IDS
            .iter()
            .map(|(_, key)| *key)
            .chain([MessageId::Unknown.key()])
            .collect();
        let labels: Vec<&str> = LabelId::IDS.iter().map(|(_, key)| *key).collect();
        known(&messages, "message", &self.messages)?;
        known(&labels, "label", &self.labels)?;
        let generated = ["title", "name"];
        let sections: [(&HashMap<String, String>, bool); 3] = [
            (&self.messages, true),
            (&self.labels, true),
            (&self.fields, false),
        ];
        for (texts, by_key) in sections {
            for (key, text) in texts {
                let allowed: &[&str] = if by_key {
                    CONTEXT_NAMES
                        .iter()
                        .find(|(k, _)| k == key)
                        .map_or(&[], |(_, names)| names)
                } else {
                    &generated
                };
                let names = placeholders(text).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}: {key:?} has a `{{` that is never closed",
                        path.display()
                    )
                })?;
                if let Some(name) = names.iter().find(|name| !allowed.contains(name)) {
                    anyhow::bail!("{}: {key:?} has no placeholder {name:?}", path.display());
                }
            }
        }
        Ok(())
    }

    fn check_complete(&self, tag: &str) -> anyhow::Result<()> {
        let unknown = (0, MessageId::Unknown.key());
        for (_, key) in MessageId::IDS.iter().chain([&unknown]) {
            if !self.messages.contains_key(*key) {
                anyhow::bail!("the default locale {tag}.json has no message {key:?}");
            }
        }
        for (_, key) in LabelId::IDS {
            if !self.labels.contains_key(*key) {
                anyhow::bail!("the default locale {tag}.json has no label {key:?}");
            }
        }
        Ok(())
    }
}

/// The values of every `language` cookie of the request, in the order the browser sent them.
fn language_cookies(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .filter_map(|cookie| cookie.split_once('='))
        .filter(|(name, _)| name.trim() == LANGUAGE_COOKIE)
        .map(|(_, value)| {
            let value = value.trim();
            value
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .unwrap_or(value)
        })
}

/// The language tags of an `Accept-Language` value, best first; `q=0` and `*` left out.
fn accepted_tags(value: &str) -> Vec<String> {
    let mut tags: Vec<(String, f32)> = value
        .split(',')
        .take(MAX_LANGUAGE_TAGS)
        .filter_map(|part| {
            let mut pieces = part.split(';');
            let tag = pieces.next()?.trim();
            let quality = pieces
                .filter_map(|piece| piece.split_once('='))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
                .map_or(1.0_f32, |(_, q)| q.trim().parse().unwrap_or(0.0))
                .clamp(0.0, 1.0);
            (quality > 0.0 && !tag.is_empty() && tag != "*").then(|| (tag.to_string(), quality))
        })
        .collect();
    tags.sort_by(|a, b| b.1.total_cmp(&a.1));
    tags.into_iter().map(|(tag, _)| tag).collect()
}

/// A language's view of the catalog: the texts for one request.
pub(crate) struct Translator<'a> {
    catalog: &'a Catalog,
    language: &'a str,
}

impl Translator<'_> {
    /// A flow or field message. Never Kratos' own text.
    pub(crate) fn message(&self, message: &UiText) -> String {
        let id = MessageId::from_id(message.id);
        if id == MessageId::Unknown {
            self.catalog.note_unmapped("message", message.id);
        }
        self.find(|locale| &locale.messages, id.key(), &message.context)
            .or_else(|| {
                self.find(
                    |locale| &locale.messages,
                    MessageId::Unknown.key(),
                    &Map::new(),
                )
            })
            .unwrap_or_default()
    }

    /// A button, link or text node; Kratos' own text when there is no translation.
    pub(crate) fn label(&self, label: &UiText) -> String {
        let id = LabelId::from_id(label.id);
        if id == LabelId::Unknown {
            self.catalog.note_unmapped("label", label.id);
            return label.text.clone();
        }
        self.find(|locale| &locale.labels, id.key(), &label.context)
            .unwrap_or_else(|| label.text.clone())
    }

    /// A field's label. A trait's is found by the trait's path (`traits.first_name`, the `name`
    /// Kratos puts in the label's context, else the field's own name); without a text for it, the
    /// schema's `title` Kratos sent. The sign-in identifier is such a label, for `traits.email`.
    pub(crate) fn field_label(&self, name: &str, label: &UiText) -> String {
        if label.id != GENERATED_LABEL_ID {
            return self.label(label);
        }
        let key = label
            .context
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(name);
        self.find(|locale| &locale.fields, key, &label.context)
            .unwrap_or_else(|| label.text.clone())
    }

    /// The text for `key` in the request's language, then in the default's, with the `context`
    /// values filled in. A text that needs a value Kratos didn't send counts as missing.
    fn find(
        &self,
        section: fn(&Locale) -> &HashMap<String, String>,
        key: &str,
        context: &Map<String, Value>,
    ) -> Option<String> {
        let default = self.catalog.default.as_str();
        for language in [self.language, default] {
            let Some(template) = self
                .catalog
                .locales
                .get(language)
                .and_then(|locale| section(locale).get(key))
            else {
                continue;
            };
            match fill(template, context) {
                Some(text) => return Some(text),
                None => tracing::warn!(
                    key,
                    language,
                    "a translation needs a value Kratos did not send"
                ),
            }
        }
        None
    }
}

/// `template` with each `{name}` replaced by the scalar `context` value of that name (`{{` and
/// `}}` are literal braces); `None` when a value is missing or isn't a scalar, or a `{` is never
/// closed.
fn fill(template: &str, context: &Map<String, Value>) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        c => name.push(c),
                    }
                }
                match context.get(&name)? {
                    Value::String(text) => out.push_str(text),
                    Value::Number(number) => out.push_str(&number.to_string()),
                    Value::Bool(flag) => out.push_str(&flag.to_string()),
                    _ => return None,
                }
            }
            c => out.push(c),
        }
    }
    Some(out)
}

/// The `context` names a text may use as `{name}`, per message or label key. For the system tests.
pub(crate) fn context_names() -> &'static [(&'static str, &'static [&'static str])] {
    CONTEXT_NAMES
}

/// The `{name}`s of `template`, or `None` when a `{` is never closed (`{{` and `}}` are literal
/// braces).
pub(crate) fn placeholders(template: &str) -> Option<Vec<&str>> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(at) = rest.find(['{', '}']) {
        let here = rest.get(at..)?;
        if let Some(tail) = here.strip_prefix("{{").or_else(|| here.strip_prefix("}}")) {
            rest = tail;
        } else if let Some(open) = here.strip_prefix('{') {
            let (name, tail) = open.split_once('}')?;
            names.push(name);
            rest = tail;
        } else {
            rest = here.strip_prefix('}')?;
        }
    }
    Some(names)
}

/// Every (place, Kratos id, key) login translates, where place is `message` or `label`.
pub(crate) fn translated_ids() -> Vec<(&'static str, u64, &'static str)> {
    let messages = MessageId::IDS
        .iter()
        .map(|(id, key)| ("message", *id, *key));
    let labels = LabelId::IDS.iter().map(|(id, key)| ("label", *id, *key));
    messages.chain(labels).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        dir
    }

    /// A default language that is complete (every text is its own key) plus `extra`.
    fn complete(extra: &[(&str, &str)]) -> String {
        let own = |key: &str| (key.to_string(), json!(format!("en:{key}")));
        let mut messages: Map<String, Value> = MessageId::IDS
            .iter()
            .map(|(_, key)| own(key))
            .chain([own("Unknown")])
            .collect();
        let mut labels: Map<String, Value> = LabelId::IDS.iter().map(|(_, key)| own(key)).collect();
        for (key, text) in extra {
            if messages.contains_key(*key) {
                messages.insert(key.to_string(), json!(text));
            } else {
                labels.insert(key.to_string(), json!(text));
            }
        }
        json!({"messages": messages, "labels": labels, "fields": {"traits.first_name": "en:First name"}})
            .to_string()
    }

    fn catalog(files: &[(&str, &str)]) -> (tempfile::TempDir, Catalog) {
        let dir = dir_with(files);
        let catalog = Catalog::load(dir.path(), "en").unwrap();
        (dir, catalog)
    }

    fn text(id: u64, text: &str, context: Value) -> UiText {
        serde_json::from_value(json!({"id": id, "text": text, "type": "info", "context": context}))
            .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn the_shipped_default_locale_is_complete() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../templates/locales");
        Catalog::load(Path::new(dir), "en").unwrap();
    }

    #[test]
    fn kratos_ids_map_to_their_variant_and_anything_else_is_unknown() {
        assert_eq!(
            MessageId::from_id(4_000_006),
            MessageId::ErrorValidationInvalidCredentials
        );
        assert_eq!(
            LabelId::from_id(1_040_003),
            LabelId::InfoSelfServiceRegistrationContinue
        );
        assert_eq!(MessageId::from_id(1), MessageId::Unknown);
        assert_eq!(LabelId::from_id(4_000_006), LabelId::Unknown);
    }

    #[test]
    fn a_message_is_translated_with_its_context_filled_in() {
        let en = complete(&[(
            "ErrorValidationPasswordMinLength",
            "At least {min_length} characters.",
        )]);
        let (_dir, catalog) = catalog(&[("en.json", &en)]);
        let message = text(
            4_000_032,
            "english",
            json!({"min_length": 8, "actual_length": 3}),
        );

        assert_eq!(
            catalog.translator("en").message(&message),
            "At least 8 characters."
        );
    }

    #[test]
    fn a_requested_language_wins_and_its_gaps_fall_back_to_the_default() {
        let en = complete(&[]);
        let sv = r#"{"messages": {"ErrorValidationInvalidCredentials": "Fel."}}"#;
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", sv)]);
        let translator = catalog.translator("sv");

        assert_eq!(translator.message(&text(4_000_006, "x", json!({}))), "Fel.");
        assert_eq!(
            translator.message(&text(4_000_007, "x", json!({}))),
            "en:ErrorValidationDuplicateCredentials"
        );
    }

    #[test]
    fn an_unknown_message_gets_the_generic_text_never_kratos_wording() {
        let (_dir, catalog) = catalog(&[("en.json", &complete(&[("Unknown", "Generic.")]))]);

        let shown =
            catalog
                .translator("en")
                .message(&text(9_999_999, "Kratos says <hi>", json!({})));

        assert_eq!(shown, "Generic.");
    }

    #[test]
    fn a_message_missing_a_context_value_gets_the_generic_text() {
        let en = complete(&[
            ("ErrorValidationPasswordMinLength", "At least {min_length}."),
            ("Unknown", "Generic."),
        ]);
        let (_dir, catalog) = catalog(&[("en.json", &en)]);

        let shown = catalog
            .translator("en")
            .message(&text(4_000_032, "x", json!({})));

        assert_eq!(shown, "Generic.");
    }

    #[test]
    fn an_unknown_label_keeps_kratos_text_and_a_known_one_is_translated() {
        let en = complete(&[("InfoSelfServiceLoginWith", "Log in with {provider}")]);
        let (_dir, catalog) = catalog(&[("en.json", &en)]);
        let translator = catalog.translator("en");

        assert_eq!(
            translator.label(&text(1, "Kratos text", json!({}))),
            "Kratos text"
        );
        assert_eq!(
            translator.label(&text(
                1_010_002,
                "Sign in with Google",
                json!({"provider": "Google"})
            )),
            "Log in with Google"
        );
    }

    #[test]
    fn a_trait_label_is_found_by_the_field_name_else_the_schema_title() {
        let (_dir, catalog) = catalog(&[("en.json", &complete(&[]))]);
        let translator = catalog.translator("en");
        let generated = text(
            GENERATED_LABEL_ID,
            "Schema title",
            json!({"title": "Schema title"}),
        );

        assert_eq!(
            translator.field_label("traits.first_name", &generated),
            "en:First name"
        );
        assert_eq!(
            translator.field_label("traits.nickname", &generated),
            "Schema title"
        );
    }

    #[test]
    fn a_generated_label_is_found_by_the_trait_kratos_names_not_the_fields_own_name() {
        let (_dir, catalog) = catalog(&[("en.json", &complete(&[]))]);
        let generated = text(
            GENERATED_LABEL_ID,
            "Schema title",
            json!({"title": "Schema title", "name": "traits.first_name"}),
        );

        assert_eq!(
            catalog
                .translator("en")
                .field_label("identifier", &generated),
            "en:First name"
        );
    }

    #[test]
    fn a_label_that_is_not_generated_ignores_the_field_name() {
        let en = complete(&[("InfoNodeLabelEmail", "E-mail")]);
        let (_dir, catalog) = catalog(&[("en.json", &en)]);

        let label = text(1_070_007, "Email", json!({}));

        assert_eq!(
            catalog
                .translator("en")
                .field_label("traits.first_name", &label),
            "E-mail"
        );
    }

    #[test]
    fn the_cookie_beats_accept_language_beats_the_default() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}"), ("de.json", "{}")]);

        let both = headers(&[("cookie", "language=de"), ("accept-language", "sv")]);
        assert_eq!(catalog.negotiate(&both), "de");
        assert_eq!(
            catalog.negotiate(&headers(&[("accept-language", "sv")])),
            "sv"
        );
        assert_eq!(catalog.negotiate(&headers(&[])), "en");
        let cookie = |value: &str| {
            catalog
                .negotiate(&headers(&[("cookie", value)]))
                .to_string()
        };
        assert_eq!(cookie("language=sv-SE"), "sv");
        assert_eq!(cookie("language=SV_se"), "sv");
    }

    #[test]
    fn accept_language_is_read_by_quality_region_falls_back_to_the_language() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}"), ("de.json", "{}")]);

        let accept = |value: &str| {
            catalog
                .negotiate(&headers(&[("accept-language", value)]))
                .to_string()
        };

        assert_eq!(accept("de;q=0.5, sv-SE;q=0.9, en;q=0.1"), "sv");
        assert_eq!(accept("fr, de;q=0"), "en");
        assert_eq!(accept("*, DE"), "de");
    }

    #[test]
    fn a_language_cookie_is_found_among_others_and_a_bad_one_falls_through() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}"), ("de.json", "{}")]);
        let negotiated = |cookie: &str| {
            let both = [("cookie", cookie), ("accept-language", "de")];
            catalog.negotiate(&headers(&both)).to_string()
        };

        assert_eq!(negotiated("a=1; language=sv; b=2"), "sv");
        assert_eq!(negotiated("language=\"sv\""), "sv");
        assert_eq!(negotiated("language=\"sv"), "de");
        assert_eq!(negotiated("language=sv\""), "de");
        assert_eq!(negotiated("language=fr"), "de");
        assert_eq!(negotiated("language=../../etc/passwd"), "de");
        assert_eq!(negotiated("mylanguage=sv; language_=sv"), "de");
        assert_eq!(negotiated("language=fr; language=sv"), "sv");
    }

    #[test]
    fn a_language_cookie_may_come_in_several_cookie_headers() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}")]);
        let mut sent = HeaderMap::new();
        sent.append("cookie", "a=1".parse().unwrap());
        sent.append("cookie", "language=sv".parse().unwrap());

        assert_eq!(catalog.negotiate(&sent), "sv");
    }

    #[test]
    fn accept_language_quality_is_clamped_and_its_name_is_case_insensitive() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}"), ("de.json", "{}")]);
        let accept = |value: &str| {
            catalog
                .negotiate(&headers(&[("accept-language", value)]))
                .to_string()
        };

        assert_eq!(accept("de;Q=0.2, sv;Q=0.9"), "sv");
        assert_eq!(accept("de;q=0.5, sv;q=inf"), "sv");
        assert_eq!(accept("de;q=nan, sv;q=0.1"), "sv");
        assert_eq!(accept("sv;q=0.1, de;q=7"), "de");
        assert_eq!(accept("de, sv;q=7"), "de");
    }

    #[test]
    fn a_tag_loses_one_subtag_at_a_time_until_a_language_matches() {
        let en = complete(&[]);
        let (_dir, catalog) =
            catalog(&[("en.json", &en), ("zh-hant.json", "{}"), ("zh.json", "{}")]);
        let accept = |value: &str| {
            catalog
                .negotiate(&headers(&[("accept-language", value)]))
                .to_string()
        };

        assert_eq!(accept("zh-Hant-TW"), "zh-hant");
        assert_eq!(accept("zh-Hans-CN"), "zh");
        assert_eq!(accept("fr-CA"), "en");
    }

    #[test]
    fn an_oversized_tag_or_list_is_ignored_not_walked() {
        let en = complete(&[]);
        let (_dir, catalog) = catalog(&[("en.json", &en), ("sv.json", "{}")]);
        let long = format!("sv{}", "-a".repeat(30_000));
        let many = format!("{}sv", "fr, ".repeat(MAX_LANGUAGE_TAGS));

        let cookie = format!("language={long}");
        let many_cookies = format!("{}language=sv", "language=fr; ".repeat(MAX_LANGUAGE_TAGS));
        assert_eq!(catalog.negotiate(&headers(&[("cookie", &cookie)])), "en");
        assert_eq!(
            catalog.negotiate(&headers(&[("cookie", &many_cookies)])),
            "en"
        );
        assert_eq!(
            catalog.negotiate(&headers(&[("accept-language", &long)])),
            "en"
        );
        assert_eq!(
            catalog.negotiate(&headers(&[("accept-language", &many)])),
            "en"
        );
        assert_eq!(
            catalog.negotiate(&headers(&[("accept-language", "sv-a-b")])),
            "sv"
        );
    }

    #[test]
    fn doubled_braces_are_literal_and_an_unclosed_one_is_missing() {
        let context = json!({"n": 3}).as_object().unwrap().clone();

        assert_eq!(
            fill("Use {{braces}} {n}", &context).as_deref(),
            Some("Use {braces} 3")
        );
        assert_eq!(fill("{unclosed", &context), None);
        assert_eq!(fill("{missing}", &context), None);
        assert_eq!(fill("a } b", &context).as_deref(), Some("a } b"));
    }

    #[test]
    fn a_non_scalar_context_value_counts_as_missing() {
        let context = json!({"list": [1], "map": {}}).as_object().unwrap().clone();

        assert_eq!(fill("{list}", &context), None);
        assert_eq!(fill("{map}", &context), None);
    }

    #[test]
    fn a_locale_cannot_replace_the_text_of_every_unmapped_label() {
        let en = complete(&[]);
        let swapped = r#"{"labels": {"Unknown": "Everything"}}"#;
        let dir = dir_with(&[("en.json", &en), ("sv.json", swapped)]);

        let error = Catalog::load(dir.path(), "en").unwrap_err().to_string();

        assert!(error.contains("Unknown"), "{error}");
    }

    #[test]
    fn an_unmapped_id_is_noted_once() {
        let (_dir, catalog) = catalog(&[("en.json", &complete(&[]))]);

        for id in [9_999_991, 9_999_991, 9_999_992] {
            catalog.note_unmapped("label", id);
        }
        catalog.note_unmapped("message", 9_999_991);

        assert_eq!(catalog.unmapped.lock().unwrap().len(), 3);
    }

    #[test]
    fn every_translated_id_is_listed_once_with_its_key() {
        let ids = translated_ids();

        assert!(ids.contains(&("message", 4_000_006, "ErrorValidationInvalidCredentials")));
        assert!(ids.contains(&("label", 1_040_003, "InfoSelfServiceRegistrationContinue")));
        let unique: HashSet<_> = ids.iter().map(|(place, id, _)| (*place, *id)).collect();
        assert_eq!(unique.len(), ids.len(), "an id is translated twice");
    }

    #[test]
    fn placeholders_follow_the_same_brace_rules_as_fill() {
        assert_eq!(placeholders("a {x} {{y}} {z}"), Some(vec!["x", "z"]));
        assert_eq!(placeholders("{{{x}}}"), Some(vec!["x"]));
        assert_eq!(placeholders("no braces } here"), Some(vec![]));
        assert_eq!(placeholders("{unclosed"), None);
    }

    #[test]
    fn every_context_names_key_is_a_message_or_label() {
        let keys: HashSet<&str> = MessageId::IDS
            .iter()
            .chain(LabelId::IDS)
            .map(|(_, key)| *key)
            .collect();

        for (key, _) in context_names() {
            assert!(keys.contains(key), "{key} is not translated by login");
        }
    }

    #[test]
    fn a_placeholder_kratos_does_not_send_stops_startup_in_any_language() {
        let en = complete(&[]);
        let load = |sv: &str| {
            let dir = dir_with(&[("en.json", &en), ("sv.json", sv)]);
            Catalog::load(dir.path(), "en")
                .map(|_| ())
                .map_err(|e| e.to_string())
        };

        let misspelled = r#"{"labels": {"InfoSelfServiceLoginWith": "Logga in med {provder}"}}"#;
        assert!(load(misspelled).unwrap_err().contains("provder"));
        let none_allowed = r#"{"messages": {"ErrorValidationEmail": "Fel {value}"}}"#;
        assert!(load(none_allowed).unwrap_err().contains("value"));
        let unclosed = r#"{"messages": {"ErrorValidationMinLength": "Minst {min_length"}}"#;
        assert!(load(unclosed).unwrap_err().contains("never closed"));
        let field = r#"{"fields": {"traits.nick": "Smek {nope}"}}"#;
        assert!(load(field).unwrap_err().contains("nope"));
        let fine = r#"{"messages": {"ErrorValidationMinLength": "Minst {min_length} {{tecken}}"},
                       "labels": {"InfoSelfServiceLoginWith": "Logga in med {provider}"},
                       "fields": {"traits.nick": "{title} ({name})"}}"#;
        assert!(load(fine).is_ok());
    }

    #[test]
    fn loading_refuses_a_broken_set_of_locales() {
        let en = complete(&[]);
        let load = |files: &[(&str, &str)]| {
            let dir = dir_with(files);
            Catalog::load(dir.path(), "en").unwrap_err().to_string()
        };

        assert!(load(&[("sv.json", "{}")]).contains("no en.json"));
        assert!(load(&[("en.json", &en), (".json", "{}")]).contains("locale tag"));
        assert!(load(&[("en.json", &en), ("sv_se.json", "{}")]).contains("locale tag"));
        let too_long = format!("{}.json", "a".repeat(MAX_TAG_LEN + 1));
        assert!(load(&[("en.json", &en), (too_long.as_str(), "{}")]).contains("locale tag"));
        assert!(load(&[("en.json", "{")]).contains("invalid locale"));
        assert!(
            load(&[("en.json", r#"{"messages": {}, "labels": {}}"#)]).contains("has no message")
        );
        assert!(
            load(&[
                ("en.json", &en),
                ("sv.json", r#"{"messages": {"Typo": "x"}}"#)
            ])
            .contains("Typo")
        );
        assert!(
            load(&[("en.json", &en), ("sv.json", r#"{"extra": {}}"#)]).contains("invalid locale")
        );
    }
}
