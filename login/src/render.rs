//! Rendering the pages: the compiled-in layout, the deployer's page templates, and the Tera
//! functions that turn Kratos' flow nodes into HTML.
//!
//! Scripts only ever come from the layout and from Kratos' script nodes, both carrying the
//! request's CSP nonce. Everything a node contributes is escaped here by hand and handed to Tera
//! as already-safe markup, so the escaping lives in one place and autoescape stays on for
//! everything else.

use crate::kratos::{
    AnchorAttributes, Flow, ImgAttributes, InputAttributes, Node, NodeKind, ScriptAttributes,
    UiText,
};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value as Json;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;
use tera::{Context, Function, Kwargs, State, Tera, TeraResult, Value};

const LAYOUT: &str = include_str!("layout.html");

/// Kratos' WebAuthn/passkey entry points: the only function names `ui.js` will call.
const TRIGGERS: [&str; 6] = [
    "oryWebAuthnRegistration",
    "oryWebAuthnLogin",
    "oryPasskeyLogin",
    "oryPasskeyLoginAutocompleteInit",
    "oryPasskeyRegistration",
    "oryPasskeySettingsRegistration",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum RenderError {
    #[error("could not load the page templates: {0}")]
    Templates(String),
    #[error("could not render {template}: {cause}")]
    Render { template: String, cause: String },
}

/// Renders pages from the deployer's templates and the compiled-in layout.
pub(crate) struct Renderer {
    /// Compiled once at startup; a changed template file needs a restart.
    tera: Tera,
}

impl Renderer {
    pub(crate) fn new(
        pages_glob: &str,
        own_origin: &str,
        kratos_origin: &str,
        providers_dir: &Path,
    ) -> anyhow::Result<Self> {
        let mut tera = Tera::new();
        // Registered first: templates are checked against the functions when they load.
        tera.register_function(
            "form",
            FormFunction {
                urls: RenderRules::new(own_origin, kratos_origin, providers_dir)?,
            },
        );
        tera.register_function("messages", MessagesFunction);
        tera.register_function("continuing", ContinuingFunction);
        tera.register_function("recovering", RecoveringFunction);
        // Child templates extend the layout, so it has to exist before they load; it is added
        // again after, so a `layout.html` in the deployer's directory can't take its place.
        tera.add_raw_template("layout.html", LAYOUT)
            .map_err(|error| RenderError::Templates(error.to_string()))?;
        tera.load_from_glob(pages_glob)
            .map_err(|error| RenderError::Templates(error.to_string()))?;
        tera.add_raw_template("layout.html", LAYOUT)
            .map_err(|error| RenderError::Templates(error.to_string()))?;
        Ok(Self { tera })
    }

    /// A page with a fresh CSP nonce, as a response with the page's security headers.
    pub(crate) fn page(&self, status: StatusCode, template: &str, mut ctx: Context) -> Response {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        ctx.insert("nonce", &nonce);
        match self.render(template, &ctx) {
            Ok(html) => (status, page_headers(&nonce), axum::response::Html(html)).into_response(),
            Err(error) => {
                tracing::error!(%error, template, "could not render a login page");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }

    fn render(&self, template: &str, ctx: &Context) -> Result<String, RenderError> {
        self.tera
            .render(template, ctx)
            .map_err(|error| RenderError::Render {
                template: template.to_string(),
                cause: error.to_string(),
            })
    }
}

/// No `form-action`: Chrome applies it to every redirect after the post, and a social sign-in
/// ends in a redirect to the provider. Scripts need the nonce; nothing else is allowed to load.
fn page_headers(nonce: &str) -> [(header::HeaderName, HeaderValue); 4] {
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; \
         font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    [
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&csp)
                .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'")),
        ),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        // Not `no-referrer`: Kratos' CSRF check wants a same-origin Referer on the post.
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin"),
        ),
    ]
}

/// What the node renderers need besides the node: which absolute URLs from Kratos are really
/// this host (and what they look like from the browser), and which providers have a logo.
#[derive(Clone)]
struct RenderRules {
    own: url::Url,
    kratos_origin: String,
    provider_logos: HashMap<String, String>,
}

impl RenderRules {
    fn new(own_origin: &str, kratos_origin: &str, providers_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            provider_logos: provider_logo_files(providers_dir)?,
            own: url::Url::parse(own_origin).map_err(|error| {
                anyhow::anyhow!("invalid WA_LOGIN_PUBLIC_URL {own_origin:?}: {error}")
            })?,
            kratos_origin: kratos_origin.to_string(),
        })
    }

    /// An https host (the prod profile requires one) only links to https.
    fn https_only(&self) -> bool {
        self.own.scheme() == "https"
    }

    /// `path?query` of a URL on this host or on Kratos' (which the proxy serves on this host),
    /// so the browser always talks to this host. `None` for anything pointing elsewhere.
    fn local(&self, raw: &str) -> Option<String> {
        let url = url::Url::options()
            .base_url(Some(&self.own))
            .parse(raw)
            .ok()?;
        let origin = url.origin().ascii_serialization();
        if origin != self.own.origin().ascii_serialization() && origin != self.kratos_origin {
            return None;
        }
        Some(match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        })
    }
}

fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn flow_argument(kwargs: &Kwargs) -> TeraResult<Flow> {
    let flow = kwargs.must_get::<&Value>("flow")?;
    let json = serde_json::to_value(flow).map_err(tera::Error::message)?;
    serde_json::from_value(json)
        .map_err(|error| tera::Error::message(format!("not a Kratos flow: {error}")))
}

struct MessagesFunction;

impl Function<TeraResult<Value>> for MessagesFunction {
    fn call(&self, kwargs: Kwargs, _: &State) -> TeraResult<Value> {
        let flow = flow_argument(&kwargs)?;
        Ok(Value::safe_string(&messages(&flow.ui.messages)))
    }

    fn is_safe(&self) -> bool {
        true
    }
}

/// Kratos' message id (`InfoSelfServiceRegistrationContinue`) for the "Continue" button of a
/// social sign-up that still needs traits. Re-check it on a Kratos upgrade: the system test
/// `google_sign_up_missing_a_trait_can_be_completed_on_the_form` fails if it moved.
const CONTINUE_LABEL_ID: u64 = 1_040_003;

/// Whether the flow is a social sign-up asking for the traits the provider didn't send. Its
/// traits and its button must be posted as one form (see `missing_only` on `form`).
struct ContinuingFunction;

impl Function<TeraResult<bool>> for ContinuingFunction {
    fn call(&self, kwargs: Kwargs, _: &State) -> TeraResult<bool> {
        let flow = flow_argument(&kwargs)?;
        Ok(flow.ui.nodes.iter().any(|node| {
            node.group == "oidc"
                && node
                    .meta
                    .label
                    .as_ref()
                    .is_some_and(|l| l.id == CONTINUE_LABEL_ID)
        }))
    }

    fn is_safe(&self) -> bool {
        false
    }
}

/// Whether the flow is the settings flow Kratos opens after a recovery. Its `request_url` is the
/// recovery submission and stays so after a rejected password, unlike the recovery message.
struct RecoveringFunction;

impl Function<TeraResult<bool>> for RecoveringFunction {
    fn call(&self, kwargs: Kwargs, _: &State) -> TeraResult<bool> {
        let flow = flow_argument(&kwargs)?;
        Ok(flow
            .request_url
            .as_deref()
            .and_then(|url| url::Url::parse(url).ok())
            .is_some_and(|url| url.path().ends_with("/self-service/recovery")))
    }

    fn is_safe(&self) -> bool {
        false
    }
}

struct FormFunction {
    urls: RenderRules,
}

impl Function<TeraResult<Value>> for FormFunction {
    fn call(&self, kwargs: Kwargs, state: &State) -> TeraResult<Value> {
        let flow = flow_argument(&kwargs)?;
        let groups = kwargs.get::<Vec<String>>("groups")?;
        let nonce = state
            .get::<String>("nonce")?
            .ok_or_else(|| tera::Error::message("no CSP nonce in the page context"))?;
        let missing_only = kwargs.get::<bool>("missing_only")?.unwrap_or(false);
        let html = form(&flow, groups.as_deref(), missing_only, &self.urls, &nonce)?;
        Ok(Value::safe_string(&html))
    }

    fn is_safe(&self) -> bool {
        true
    }
}

fn messages(messages: &[UiText]) -> String {
    if messages.is_empty() {
        return String::new();
    }
    let mut html = String::from("<ul class=\"messages\">");
    for message in messages {
        let _ = write!(
            html,
            "<li class=\"message message-{}\">{}</li>",
            message_kind(message),
            escape(message_text(message))
        );
    }
    html.push_str("</ul>");
    html
}

/// Kratos' message id (`InfoSelfServiceRecoverySuccessful`) shown on settings after a recovery.
/// Kratos' text offers social sign-in whether or not a provider is configured. Re-check it on a
/// Kratos upgrade: `recovery_ends_every_old_session_and_purges_credentials_and_oidc_links` fails
/// if it moved.
const RECOVERY_SUCCESSFUL_ID: u64 = 1_060_001;

fn message_text(message: &UiText) -> &str {
    match message.id {
        RECOVERY_SUCCESSFUL_ID => {
            "Your account is recovered. Set a new password below within the next few minutes, \
             or you will have to recover it again."
        }
        _ => &message.text,
    }
}

fn message_kind(message: &UiText) -> &'static str {
    match message.kind.as_str() {
        "error" => "error",
        "success" => "success",
        _ => "info",
    }
}

/// The nodes of the chosen `groups` (every group when `None`) as one `<form>`, and their script
/// nodes after it. Hidden inputs of the `default` group (the CSRF token) go into every form; its
/// visible ones (the identifier) only when `default` is asked for. A form with nothing to show
/// is left out. With `missing_only`, a visible `default`-group field that has a value and no
/// messages is left out too.
fn form(
    flow: &Flow,
    groups: Option<&[String]>,
    missing_only: bool,
    urls: &RenderRules,
    nonce: &str,
) -> TeraResult<String> {
    let chosen = |node: &Node| {
        let in_groups = match groups {
            None => true,
            Some(groups) => groups.contains(&node.group) || is_hidden_default(node),
        };
        in_groups && !(missing_only && is_settled_field(node))
    };
    let nodes: Vec<&Node> = flow.ui.nodes.iter().filter(|node| chosen(node)).collect();

    let mut html = String::new();
    let shows_something = nodes.iter().any(|node| {
        !matches!(node.kind, NodeKind::Script(_) | NodeKind::Unknown) && !is_hidden_input(node)
    });
    if shows_something {
        let method = if flow.ui.method.eq_ignore_ascii_case("get") {
            "get"
        } else {
            "post"
        };
        // A form that can't post to this host would just be dead.
        let action = urls.local(&flow.ui.action).ok_or_else(|| {
            tera::Error::message("the flow's form action is not on this host or Kratos'")
        })?;
        let _ = write!(
            html,
            "<form class=\"flow-form\" method=\"{method}\" action=\"{}\">",
            escape(&action)
        );
        for node in &nodes {
            if !matches!(node.kind, NodeKind::Script(_)) {
                html.push_str(&render_node(node, urls));
            }
        }
        html.push_str("</form>");
    }
    for node in &nodes {
        if let NodeKind::Script(script) = &node.kind {
            html.push_str(&render_script(script, urls, nonce));
        }
    }
    Ok(html)
}

fn is_settled_field(node: &Node) -> bool {
    let NodeKind::Input(input) = &node.kind else {
        return false;
    };
    let filled = match &input.value {
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Null) | None => false,
        Some(_) => true,
    };
    node.group == "default"
        && !matches!(input.kind.as_str(), "hidden" | "submit" | "button")
        && filled
        && node.messages.is_empty()
}

fn is_hidden_input(node: &Node) -> bool {
    matches!(&node.kind, NodeKind::Input(input) if input.kind == "hidden")
}

fn is_hidden_default(node: &Node) -> bool {
    node.group == "default" && is_hidden_input(node)
}

fn render_node(node: &Node, urls: &RenderRules) -> String {
    let mut html = match &node.kind {
        NodeKind::Input(input) => render_input(node, input, urls),
        NodeKind::Text(text) => {
            format!(
                "<p class=\"node-text\"{}>{}</p>",
                id_attribute(&text.id),
                escape(&text.text.text)
            )
        }
        NodeKind::Img(img) => render_img(img),
        NodeKind::A(anchor) => render_anchor(anchor, urls),
        NodeKind::Div(div) => format!("<div{}></div>", id_attribute(&div.id)),
        NodeKind::Script(_) | NodeKind::Unknown => String::new(),
    };
    if !node.messages.is_empty() && !matches!(node.kind, NodeKind::Input(_)) {
        html.push_str(&messages(&node.messages));
    }
    html
}

fn id_attribute(id: &str) -> String {
    if id.is_empty() {
        String::new()
    } else {
        format!(" id=\"{}\"", escape(id))
    }
}

/// `value` as Kratos sends it: a string, or a scalar that reads the same as one.
fn value_text(value: Option<&Json>) -> Option<String> {
    match value? {
        Json::String(text) => Some(text.clone()),
        Json::Number(number) => Some(number.to_string()),
        Json::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// The trigger name if it is one `ui.js` knows; anything else is dropped rather than echoed.
fn known_trigger(name: Option<&str>) -> Option<&str> {
    name.filter(|name| TRIGGERS.contains(name))
}

fn trigger_attributes(input: &InputAttributes) -> String {
    let mut html = String::new();
    if let Some(name) = known_trigger(input.onclick_trigger.as_deref()) {
        let _ = write!(html, " data-wa-trigger=\"{name}\"");
    }
    if let Some(name) = known_trigger(input.onload_trigger.as_deref()) {
        let _ = write!(html, " data-wa-onload=\"{name}\"");
    }
    html
}

fn provider_logo(id: &str, urls: &RenderRules) -> String {
    match urls.provider_logos.get(id) {
        Some(file) => format!(
            "<img src=\"/providers/{}\" alt=\"\" height=\"22\">",
            escape(file)
        ),
        None => String::new(),
    }
}

/// Provider id (the file stem, exactly) to file name, for the images in `dir`. A missing
/// directory means no logos; two files for one provider stop startup. File names outside
/// `[A-Za-z0-9_-]` plus a known extension are ignored, so they never need URL-encoding.
fn provider_logo_files(dir: &Path) -> anyhow::Result<HashMap<String, String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => anyhow::bail!(
            "cannot read the provider logos in {}: {error}",
            dir.display()
        ),
    };
    let mut logos = HashMap::new();
    for entry in entries.flatten() {
        let Ok(file) = entry.file_name().into_string() else {
            continue;
        };
        let Some((id, extension)) = file.rsplit_once('.') else {
            continue;
        };
        let plain = id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !plain || !matches!(extension, "webp" | "png" | "svg" | "jpg") {
            continue;
        }
        if let Some(previous) = logos.insert(id.to_string(), file.clone()) {
            anyhow::bail!("two logos for provider {id:?}: {previous} and {file}");
        }
    }
    Ok(logos)
}

fn render_input(node: &Node, input: &InputAttributes, urls: &RenderRules) -> String {
    let value = value_text(input.value.as_ref());
    let value_attribute = |value: &Option<String>| match value {
        Some(value) => format!(" value=\"{}\"", escape(value)),
        None => String::new(),
    };
    let name = escape(&input.name);
    let group = escape(&node.group);
    let disabled = if input.disabled { " disabled" } else { "" };
    match input.kind.as_str() {
        "hidden" => format!(
            "<input type=\"hidden\" name=\"{name}\"{}{}>{}",
            value_attribute(&value),
            trigger_attributes(input),
            messages(&node.messages)
        ),
        kind @ ("submit" | "button") => {
            let label = node
                .meta
                .label
                .as_ref()
                .map(|label| label.text.clone())
                .filter(|text| !text.is_empty())
                .or_else(|| value.clone())
                .unwrap_or_else(|| input.name.clone());
            let logo = value
                .as_deref()
                .filter(|_| node.group == "oidc" && input.name == "provider")
                .map(|id| provider_logo(id, urls))
                .unwrap_or_default();
            format!(
                "<button class=\"btn btn-{}\" type=\"{kind}\" name=\"{name}\"{}{}{disabled}>{logo}{}</button>{}",
                escape(&node.group),
                value_attribute(&value),
                trigger_attributes(input),
                escape(&label),
                messages(&node.messages)
            )
        }
        kind => {
            let kind = match kind {
                "password" | "number" | "checkbox" | "email" | "tel" | "url" | "date"
                | "datetime-local" => kind,
                _ => "text",
            };
            let label = node
                .meta
                .label
                .as_ref()
                .map(|label| label.text.as_str())
                .unwrap_or_default();
            let mut html = format!(
                "<div class=\"field\"><label for=\"f-{group}-{name}\">{}</label>",
                escape(label)
            );
            let _ = write!(
                html,
                "<input type=\"{kind}\" id=\"f-{group}-{name}\" name=\"{name}\"{}",
                value_attribute(&value)
            );
            if let Some(autocomplete) = &input.autocomplete {
                let _ = write!(html, " autocomplete=\"{}\"", escape(autocomplete));
            }
            if let Some(maxlength) = input.maxlength {
                let _ = write!(html, " maxlength=\"{maxlength}\"");
            }
            if let Some(pattern) = &input.pattern {
                let _ = write!(html, " pattern=\"{}\"", escape(pattern));
            }
            if input.required {
                html.push_str(" required");
            }
            html.push_str(disabled);
            html.push_str(&trigger_attributes(input));
            html.push('>');
            html.push_str(&messages(&node.messages));
            html.push_str("</div>");
            html
        }
    }
}

/// A URL worth showing to a browser: https (http too, unless this host is https), or a path on
/// this host (never `//host`).
fn is_web_url(raw: &str, urls: &RenderRules) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.starts_with("https://")
        || (lower.starts_with("http://") && !urls.https_only())
        || is_local_path(raw)
}

fn is_local_path(raw: &str) -> bool {
    raw.starts_with('/') && !raw.starts_with("//") && !raw.starts_with("/\\")
}

fn render_img(img: &ImgAttributes) -> String {
    let src = img.src.to_ascii_lowercase();
    // The page's CSP only loads images from this host and `data:` URIs.
    if !(is_local_path(&img.src) || src.starts_with("data:image/")) {
        return String::new();
    }
    let mut html = format!("<img src=\"{}\" alt=\"\"", escape(&img.src));
    if let Some(width) = img.width {
        let _ = write!(html, " width=\"{width}\"");
    }
    if let Some(height) = img.height {
        let _ = write!(html, " height=\"{height}\"");
    }
    html.push_str(&id_attribute(&img.id));
    html.push('>');
    html
}

fn render_anchor(anchor: &AnchorAttributes, urls: &RenderRules) -> String {
    let title = escape(&anchor.title.text);
    if is_web_url(&anchor.href, urls) {
        format!(
            "<a href=\"{}\"{}>{title}</a>",
            escape(&anchor.href),
            id_attribute(&anchor.id)
        )
    } else {
        format!("<span{}>{title}</span>", id_attribute(&anchor.id))
    }
}

/// A Kratos script node with `integrity` kept, served from this host's proxy, and this request's
/// nonce instead of Kratos'. A script that points anywhere else is not rendered.
fn render_script(script: &ScriptAttributes, urls: &RenderRules, nonce: &str) -> String {
    let Some(src) = urls.local(&script.src) else {
        return String::new();
    };
    let mut html = format!("<script src=\"{}\"", escape(&src));
    if script.is_async {
        html.push_str(" async");
    }
    for (name, value) in [
        ("crossorigin", &script.crossorigin),
        ("integrity", &script.integrity),
        ("referrerpolicy", &script.referrerpolicy),
    ] {
        if let Some(value) = value {
            let _ = write!(html, " {name}=\"{}\"", escape(value));
        }
    }
    let _ = write!(html, " nonce=\"{nonce}\"");
    html.push_str(&id_attribute(&script.id));
    html.push_str("></script>");
    html
}
