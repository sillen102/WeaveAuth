# AGENTS.md (login)

Scoped to `login/` — overrides the repo-root `AGENTS.md` where they conflict.

login is the UI for Ory Kratos (flows) and Hydra (login, logout and consent challenges). It
renders Kratos' flow JSON server-side and is the **only** way a browser reaches Kratos:
`/self-service/*` and `/.well-known/ory/*` are proxied to Kratos' public API (per-client
rate limits, plus a per-identifier throttle on password submissions).

## Scripts come from the layout and from Kratos, never from a deployer

`login/src/layout.html` is compiled into the binary. It owns `<head>`, loads `/ui.js` (also
compiled in; it binds the passkey/WebAuthn triggers Kratos puts on its nodes) and defines the
`page` and `title` blocks. Every page response carries a per-request CSP nonce: only the layout
script and Kratos' script nodes (rendered by `form()`, `integrity` kept, Kratos' nonce swapped
for ours) get it, so nothing else can run.

`templates/pages/*.html` (`login`, `registration`, `recovery`, `verification`, `settings`,
`error`) are the deployer-replaceable part. Each one `{% extends "layout.html" %}` and fills
`{% block page %}`. A deployer supplies **plain HTML and CSS only**: no `<script>`, no inline
event handlers, no `style=` attributes, no `javascript:` URLs. The CSP enforces it
(`default-src 'none'`, `script-src 'nonce-…'`, `style-src 'self'`), and a test greps the shipped
templates. A `layout.html` dropped into the pages directory is ignored.

- A page's data comes from Tera functions and context, never from client-side code:
  - `form(flow=flow, groups=[...])`: the flow's nodes of those groups as one `<form>` (every
    group when `groups` is left out), plus the group's script nodes. The `default` group's
    hidden inputs (the CSRF token) go into every form; its visible ones (the identifier) only
    when `"default"` is listed. A form with nothing visible renders nothing.
  - `messages(flow=flow)`: the flow's messages.
  - `continuing(flow=flow)`: a social sign-up asking for missing traits; `recovering(flow=flow)`:
    the settings flow Kratos opens after a recovery.
  - Context: `flow` (Kratos' JSON), `nonce`, `bff_url`, `login_url`, `registration_url`,
    `recovery_url` (these keep the Hydra challenge or `return_to` the flow started with).
    `error.html` gets `error.message`.
- Tera functions take keyword arguments only.
- Everything a node contributes is escaped by hand in `render.rs` and returned as safe markup;
  autoescape stays on for the rest. Link and image URLs must be http(s) (https only when
  `WA_LOGIN_PUBLIC_URL` is https, i.e. in prod), a path on this host or (images, whose CSP is
  `img-src 'self' data:`, so only these two) `data:image/`;
  script sources are reduced to their path on this host, and a form whose action isn't on this
  host or Kratos' fails the render (`500`, logged) rather than producing a dead form. Input ids
  are `f-<group>-<name>`. A trigger name outside the six Kratos defines is dropped, never echoed.
- No `form-action` in the CSP: Chrome applies it to the redirect chain after a post, which for
  a social sign-in ends at the provider.
- Templates are compiled once at startup (a broken one stops it, an edited one needs a restart).
  The CSP nonce reaches `form()` through the page context.
- When a template needs a new value, add it to the context in `pages.rs`.

Provider logos live in `templates/providers/<provider id>.{webp,png,svg,jpg}` (next to `pages/`;
the stem must be `[A-Za-z0-9_-]` and equal the provider id exactly, and two files for one id stop
startup). A social sign-in button shows the logo for its provider id, if there is one, found once
at startup (a new logo needs a restart; the directory itself is served live at `/providers/*`).
The button text is Kratos' own: set the provider's `label` in `ory/kratos/oidc-*.yml`. Responses
carry `Cache-Control: public, max-age=86400` (not on errors), `nosniff` and a sandboxing CSP, and
no directory index. They are still on login's origin: don't put untrusted SVGs there.

Enforce the template rules with `grep -rn '<script\|on[a-z]*="\|style="' templates/pages/`,
which should return nothing.

## Pages

- `/login` and `/registration` start a Kratos flow only from a Hydra `login_challenge`
  (redirecting to `/self-service/<flow>/browser?login_challenge=…` on this host); the proxy
  below lets anyone start `/self-service/{login,registration}/browser` directly. Without a
  challenge or a flow they go to bff's `/login` with `redirect_uri` (query, else
  `WA_DEFAULT_REDIRECT_URI`); with neither, they're a 400, never a redirect to login's own
  origin (that loops through bff for a signed-in user).
- `/recovery`, `/verification`, `/settings` start their own flows.
- `?flow=ID` fetches the flow from Kratos server-side, forwarding the browser's `Cookie`. An
  expired flow (404/410) or one that isn't this browser's (403, Kratos' CSRF check) starts over;
  a settings flow without a session (401) goes to `/login`.
- `/logout?logout_challenge` (only when Hydra says `rp_initiated`, i.e. the app started it):
  ends the Kratos session (cookies passed on to the browser), then accepts Hydra's logout. All of it
  is in `challenges.rs`.
- `/consent?consent_challenge` accepts only for `WA_BFF_CLIENT_ID` and scopes within
  `openid offline_access`; anything else is rejected. It grants the audience the request asked
  for and nothing else (the client's registered audience is not added).
- `/error?id=` shows a fixed text chosen by the status of Kratos' error, never its `message` or
  `reason` (they can carry what the link's maker put in `return_to`). Hydra's
  `error`/`error_description` query text is never shown (anyone can craft that link).

## The Kratos proxy

- Only `GET` and `POST` on `/self-service/*` and `GET` on `/.well-known/ory/*`; paths with
  `..` segments, a `%` or a `//` are refused (`404`; Kratos decodes the path, the throttle
  compares it raw), and so are Kratos' native-client flows (a last segment of `api`: no CSRF
  protection, no browser behind them). Request headers forwarded: `Cookie`, `Content-Type`,
  `Accept`, `Accept-Language`, `User-Agent`, `Origin`, `Referer`, plus `True-Client-IP`, set from
  the client address the rate limiter resolved (never taken from the request). Response headers
  kept: `Content-Type`, `Cache-Control` (`no-store` when Kratos sent none), `Location`,
  `Retry-After`, `Content-Disposition`, every `Set-Cookie`; login adds `nosniff` and a locked-down
  `Content-Security-Policy`. `/static` gets `nosniff` and `no-cache`, `/providers` `nosniff` and a day of caching.
- `POST /self-service/login` in another case or with a trailing `/` is `404`, so the throttle can't be sidestepped.
- Two per-client buckets (`common::rate_limit`, `WA_TRUSTED_PROXIES`): submissions (`POST`),
  and everything else, pages included. `/health`, `/ui.js`, `/static/*` and `/providers/*` have none.
- `POST /self-service/login` with `method=password` also goes through `throttle.rs`: keyed on
  a hash of the trimmed, lowercased `identifier`, whatever the address; 5 free attempts, then
  one per 30 s, then one per 5 min; a delay, not a lockout; known and unknown identifiers look
  the same. Attempts are counted when admitted (so parallel requests can't overshoot) and
  settled from Kratos' answer: a redirect away from login's pages that sets a non-empty
  `ory_kratos_session` cookie (or a 2xx/422 that does) clears the count, a refusal
  before any check (403, 429, 5xx, the error page) is given back, anything else stays counted.
  Form and JSON bodies are read (`password_identifier`, Kratos' deprecated alias, counts as
  `identifier`); other encodings are refused, and so is a body that repeats `identifier` or
  `method`, a JSON body serde can't parse, a non-string JSON `identifier`/`method`, and a JSON
  key that matches one of them only case-insensitively or has non-ASCII characters (Go's
  decoder would read it). A full table evicts a tenth of its entries (those not yet delaying
  anyone first, oldest first) instead of leaving new identifiers untracked.
