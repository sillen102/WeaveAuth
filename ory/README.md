# Ory configuration (Kratos + Hydra)

Config for the two Ory services WeaveAuth sits on: Kratos (identities, password, Google/social,
passkeys, recovery, verification, email) and Hydra (OIDC, JWT access tokens, JWKS, refresh). Pinned to
`oryd/kratos:v26.2.0` and `oryd/hydra:v26.2.0`. Every key below was checked against that release's config
schema and against a running stack (see [Behaviour checks](#behaviour-checks)).

```
ory/
  kratos/
    kratos.yml                    base config, verified-email-first
    session-on-registration.yml   overlay: sign in right after registration (second -c file)
    oidc-google.yml               overlay: the Google provider (second -c file)
    oidc-google-phone.yml         the same plus the scope for the phone number; load one of the two
    identity.schema.json          traits: email, first_name, last_name, phone_number (last one optional)
    oidc/{google,generic}.jsonnet claim mappers
    hooks/*.jsonnet               web hook request bodies
    courier-templates/            verification and recovery code mails (Go templates)
    start.sh                      container entrypoint: fills secrets into the config, then serves
  hydra/
    hydra.yml
    init-bff-client.sh            creates/updates the one OAuth2 client (bff)
    start.sh                      container entrypoint: fills the hooks key into the config, then serves all|public|admin
  checks/                         the behaviour checks: stub for weaveauth, fake IdP, driver script
```

URLs in both files are `local-prod`'s (`https://login.localhost:8443`, `http://weaveauth:1983`, ...). For a
deployment change these, nothing else is host-specific:

| Key | Set it to |
|---|---|
| Kratos `serve.public.base_url`, every `selfservice.flows.*.ui_url`, `methods.oidc.config.base_redirect_uri`, `methods.passkey.config.rp.{id,origins}` | the login host (browser-facing). `rp.id` must be a registrable suffix of the origin's host and can never change without losing every passkey |
| Kratos `selfservice.default_browser_return_url`, `allowed_return_urls` | `WA_DEFAULT_REDIRECT_URI`; the login and bff origins |
| Kratos `selfservice.flows.settings.after.password.default_browser_return_url`, `selfservice.flows.logout.after.default_browser_return_url` | the login host's `/login` |
| Kratos `serve.admin.base_url`, `oauth2_provider.url`, hook `url`s, `courier.smtp.connection_uri` | internal addresses |
| Hydra `urls.self.issuer`, `urls.{login,consent,logout,error}` | the login host; `urls.post_logout_redirect` and the client's post-logout URI: a path on the bff origin |
| Hydra `urls.identity_provider.url`, `oauth2.token_hook.url` | Kratos admin; hooks |

Secrets never live in these files: `DSN`, `SECRETS_COOKIE`, `SECRETS_CIPHER` (Kratos, exactly 32 chars) and
`SECRETS_SYSTEM`, `SECRETS_COOKIE` (Hydra) are env vars. The hooks API key has to appear in the config
(`auth.config.value` of every web hook, which Ory cannot read from env), so it is written as
`@WA_HOOKS_API_KEY@` and `start.sh` substitutes it into a copy under `/tmp` (mode 600) before serving. The
substitution is a `sed`, so `start.sh` refuses to start unless the key (and Kratos' `GOOGLE_CLIENT_ID` /
`GOOGLE_CLIENT_SECRET`) only has `A-Z a-z 0-9 _ . -`: use a hex or base64url key.

## Kratos

### Identity schema

`traits.email` (required, `format: email`) is the identifier for password and passkey and the address for
verification and recovery. `first_name` and `last_name` are required; `phone_number` is optional
(Google's id_token carries none; hooks can read it with `profile_apis`).
`additionalProperties: false`: a deployer's extra registration fields must be added to the schema
(optional properties; hooks forwards every trait except email to the registration webhook as
`fields`).

### Methods and flows

| Setting | Value | Why |
|---|---|---|
| `methods.password`, `passkey`, `oidc` | enabled | the sign-in methods |
| `methods.code` | enabled, `passwordless_enabled` left false | recovery and verification use codes (`flows.{recovery,verification}.use: code`); code *login* stays off |
| `methods.oidc.config.providers` | `[]` in the base file | providers come from a second `-c` file, like `oidc-google.yml`, because their client secrets need rendering |
| provider `account_linking_mode` | default `confirm_with_existing_credential` | an OIDC login whose email belongs to another identity must first sign in with that identity's credential. Never `automatic` |
| `oauth2_provider.url` | Hydra admin (`hydra-admin` in local-prod) | Kratos accepts Hydra's login challenge itself, for every flow (check 5) |
| `flows.registration.style` | default `profile_first` | two steps: traits first, then the method (password, passkey, provider). `enable_legacy_one_step: true` gives one screen |
| `flows.settings.after.password.default_browser_return_url` | login's `/login` | the password-change hook ends the app's bff and Hydra sessions, so a saved password leads to sign-in (through bff, back to `WA_DEFAULT_REDIRECT_URI`) instead of the settings form; a settings flow's `return_to` (copied from the recovery's, when it had one) wins over it. Kratos asks for the password again there: Hydra's login session is gone, so it does not accept the challenge on the existing session |
| `flows.login.style` | default `unified` | identifier + password + passkey + providers on one screen |
| `courier.template_override_path` | `courier-templates/` | `verification_code/valid` and `recovery_code/valid`, written for this repo; anything not overridden uses Kratos's built-ins |
| `courier.smtp.connection_uri` | `smtp://mail:1025/` | STARTTLS with certificate verification (default). Never add `skip_ssl_verify` |
| `--watch-courier` | passed by `start.sh` | the courier runs inside the serve process |

### Verified-email-first (base) and its overlay

Base: `registration.after.<method>.hooks` is `[web_hook after-registration, show_verification_ui]` for
`password`, `passkey` and `oidc` (YAML anchor, written once), and `login.after.hooks` is
`[require_verified_address]`. There is no `session` hook, so nobody is signed in until the address is
verified. What Kratos does with an OAuth2 login challenge in that setup (checks 5 and 6; a JSON
registration hands out no `login_verifier`, `run_checks.py json`). hooks' token hook still refuses unverified
addresses (`require_verified_email`, see Hooks below), so a deployment that signs in earlier gets no token either:

- Registration: the verification flow keeps the challenge. After the code is accepted Kratos accepts Hydra's
  login request, and the browser continues to Hydra. A provider that asserts `email_verified: true` skips the
  verification step, because the mapper sets the verified address.
- Login with an unverified address (password, passkey or provider): `require_verified_address` starts a
  verification flow and mails a code, and does not accept Hydra's request. Quirk: entering the code in *that*
  flow ends on `/error` (404, the login session was never persisted). The address is verified by then, so the
  user just signs in again. The login `/error` page should say so.

Overlay: `-c kratos.yml -c session-on-registration.yml` repeats the web hook and replaces `show_verification_ui`
with `session`, and empties `login.after.hooks`. It must repeat the hook because arrays replace, not merge.
Local-prod: `KRATOS_SESSION_ON_REGISTRATION=1` (or `true`) in `.env`; any other non-empty value stops Kratos
from starting, so a typo can't silently drop verified-email-first. Two traps that follow from how Kratos
assembles hooks: registration's global `after.hooks` can only hold web hooks, and strategy hooks *replace* the global ones (they are never
merged): a deployer who adds `login.after.oidc.hooks` silently loses `require_verified_address` for OIDC.

### Explicit defaults

`kratos.yml` sets what is otherwise implicit: `password.config` has `haveibeenpwned_enabled: true`,
`ignore_network_errors: false` (a Pwned Passwords outage refuses new passwords rather than skipping the check; the system tests render it as `true`, since their host may not reach the service) and
`min_password_length: 8`; login's `WA_KRATOS_SESSION_COOKIE` must equal `session.cookie.name` (default `ory_kratos_session`); `session.lifespan` is `24h` and the session cookie `SameSite=Lax`. Registration reveals
whether an address is taken (Kratos' standard behaviour); that is an accepted trade-off. Both Ory services start
with `--sqa-opt-out` (no usage telemetry), Hydra with `strategies.scope: exact`. HSTS is not set by any WeaveAuth
service (bff strips an upstream's): the ingress must send `Strict-Transport-Security`, as local-prod's Caddy does.

### Hooks

The request body of every Kratos web hook is rendered from `hooks/*.jsonnet`; `ctx` is Kratos's template
context. Each call carries `Authorization: Bearer <WA_HOOKS_API_KEY>`, `Content-Type: application/json`,
`Ory-Webhook-Request-Id` and `Ory-Webhook-Trigger-Id` (the trigger id is the same across retries).

| Hook | Body (tested) | Runs | Notes |
|---|---|---|---|
| after registration (`after-registration.jsonnet`) | `{identity_id, email, email_verified, traits, flow_id, method, provider}`; `method` is `"oidc"` or null (null for password and passkey), `provider` the provider id from the callback URL or null | after the identity is persisted, no `response.parse` | the context has no provider tokens or scopes; read them from Kratos admin (check 7). Non-2xx or a timeout aborts the flow with `/error` and leaves the identity behind: hooks deletes it |
| after recovery (`after-recovery.jsonnet`) | `{identity_id}` | after the recovery code is accepted, **before** the recovery session exists | the context has **no session**. Purge every Kratos session of the identity inside the hook (`DELETE /admin/identities/{id}/sessions`): the new recovery session is created afterwards and survives (tested) |
| after password change (`after-password-change.jsonnet`) | `{identity_id, session_id}` | settings flow, after the password is stored | `session_id` is the session that changed it; revoke the others |

A hook must answer within seconds: Kratos waits synchronously and retries a 5xx 3 times before failing the flow. Use
`response.parse: true` only for hooks that must block *before* persistence; such a hook sees an identity that
is not yet readable through Kratos admin.

### OIDC providers

`oidc/generic.jsonnet` works for any OpenID Connect provider with an `email` claim, including the
system-tests fake IdP; `oidc/google.jsonnet` is the same mapping for Google with a comment on adding claims
(add the claim to the schema too). Both set `verified_addresses` only when the id_token has
`email_verified: true`.

Google: create an OAuth client (Web application) and register the redirect URI
`https://<login host>/self-service/methods/oidc/callback/google`. Kratos needs egress to Google and its
public CAs (local-prod's `egress` network). Provider files go in a second `-c` file (`oidc-google.yml`, or
`oidc-google-phone.yml` when hooks' `profile_apis.google` should read the phone number: it repeats the provider
with one more scope, because a later `-c` file replaces the `providers` list); the
client id and secret are rendered from `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`, and `start.sh` refuses to
load either file while either is empty. The file's provider `id`
is the last path segment of the callback URL. Its `label` (`Google`) is the name on login's button ("Sign in
with Google"; without it Kratos shows the id), and login shows `templates/providers/<id>.<ext>` as its logo.

### Kratos upgrades

login finds the "Continue" step of a social sign-up that still needs traits by Kratos' message id
`1040003` (`InfoSelfServiceRegistrationContinue`, `CONTINUE_LABEL_ID` in `login/src/render.rs`). Re-check it
when `oryd/kratos` is bumped: if it moved, that step renders as two forms and the user can't continue. The
system test `google_sign_up_missing_a_trait_can_be_completed_on_the_form` catches it.

## Hydra

| Setting | Value | Why |
|---|---|---|
| `strategies.access_token` | `jwt` | stateless tokens verified against the JWKS. They stay valid until `exp` whatever is revoked, so keep `ttl.access_token` short (15m) |
| `urls.self.issuer` | login host | the `iss` of every token. The discovery document and JWKS are also served on Hydra's internal port (with the https issuer URLs inside), so bff and downstream services fetch token/JWKS from the internal URL and only compare `iss` |
| `urls.{login,consent,logout,error}` | login host pages | `consent` is always called: `skip_consent` does nothing in Hydra 26 (check 1) |
| `urls.identity_provider.url` | Kratos admin | at logout Hydra disables the Kratos session itself (check 9) |
| `oauth2.pkce.enforced` | `true` | every authorization request needs a `code_challenge`, whatever the client sends (bff always sends S256); without it the code is refused at the end of the flow with `invalid_request` |
| `oauth2.token_hook` | hooks, `api_key` auth | adds claims on every grant, refresh included (check 2) |
| `strategies.scope` | `exact` | a requested scope must equal a granted one; no wildcard matching |
| `oauth2.allowed_top_level_claims` | `[roles, email, email_verified]` | hook-returned claims in this list become top-level JWT claims; others go under `ext`. Keep in step with the claims webhook. `mirror_top_level_claims: false` |
| `oauth2.grant.refresh_token.rotation_grace_period` / `rotation_grace_reuse_count` | `10s` / `2` | tolerates a lost response; reuse after the grace period revokes the whole chain (tested) |
| `ttl.*` | access 15m, id 15m, refresh 720h, auth code 5m | refresh TTL is what bff must use for `refresh_expires_at` |

`hydra/start.sh` takes `all` (default), `public` or `admin`. Local-prod runs `public` (`hydra`, on `edge` and
`internal`) and `admin` (`hydra-admin`, on `internal` only) as two containers on the same database, so the
Hydra that Caddy can reach has no admin API: a wrong Caddy matcher cannot expose it. Everything that needs
the admin API (Kratos' `oauth2_provider.url`, hooks' and login's `WA_HYDRA_ADMIN_URL`, `hydra-init`, key
rotation) points at `hydra-admin:4445`; bff's token and JWKS calls go to `hydra:4444`.

`serve.tls.allow_termination_from` is **not** needed: Hydra answers behind Caddy (and plain HTTP on the
internal network) without it.

### The bff client

`hydra/init-bff-client.sh` (run by the `hydra-init` one-shot; idempotent, safe to rerun after a change; it
passes the client as a mode-600 JSON file, so the secret is not on the command line):
confidential, `client_secret_basic`, grants `authorization_code` + `refresh_token`, response type `code`,
scopes `openid offline_access`, `redirect_uris [bff/callback]`, `audience [weaveauth]` (an **allow-list**, see
check 8), `access_token_strategy jwt`, `backchannel_logout_uri http://weaveauth:8082/backchannel-logout` with
`session_required`, and one `post_logout_redirect_uri`: Hydra requires it to match a redirect URI's
scheme/host/port, so it has to be a path on the bff origin (here `/logged-out`).

### Key rotation

Hydra creates `hydra.openid.id-token` and `hydra.jwt.access-token` on first start. To rotate the JWT access
token signing key (tested, no restart needed):

```
hydra create jwks hydra.jwt.access-token --alg RS256 --use sig   # ORY_SDK_URL=http://hydra-admin:4445
```

New tokens are signed with the new key at once; the old key stays in `/.well-known/jwks.json` so tokens in
flight keep verifying. Once the old key is older than the access token TTL plus the longest JWKS cache of any
consumer, remove it: `hydra delete jwk hydra.jwt.access-token <old kid>`. Do the same with
`hydra.openid.id-token` for id tokens (bff verifies those: its JWKS cache must refetch on an unknown `kid`).
Run it as a scheduled job. The system secrets rotate by prepending a new value to `secrets.system` /
`secrets.cookie` (Hydra) and `secrets.cookie` / `secrets.cipher` (Kratos); keep the old one second until
everything it signed or encrypted has expired.

## Behaviour checks

Reproducible: `ory/checks/run_checks.py` runs them against the compose stack with a stub in place of the
weaveauth image (`ory/checks/stub.py`: logs every request, answers the hooks with canned data) and a fake IdP
(mock-oauth2-server, three issuers: verified email, unverified email, an address that already has a password).

```
cd local-prod && ./gen-certs.sh && ./gen-secrets.sh
docker compose -f docker-compose.yml -f ../ory/checks/docker-compose.checks.yml up -d
python3 -m venv /tmp/v && /tmp/v/bin/pip install soft-webauthn     # optional: software passkey authenticator
/tmp/v/bin/python ../ory/checks/run_checks.py            # or: run_checks.py 3 7 hooks link routing
docker compose -f docker-compose.yml -f ../ory/checks/docker-compose.checks.yml down -v
```

The override publishes Hydra/Kratos admin and the fake IdP on loopback (34445, 34434, 18080) so the driver
can inspect state; never do that outside a check. The driver is a stand-in browser: it follows redirects by
hand with cookie jars through Caddy (`https://login.localhost:8443`, TLS verified against `certs/ca.crt`), and
does bff's job at the token endpoint from a container on the internal network
(`http://hydra:4444`, `client_secret_basic`), so the internal-URL path is exercised as well.

### RESULTS

Run on 2026-10-07 against Kratos/Hydra v26.2.0, Postgres 18, from `docker compose down -v`.

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Does `skip_consent` bypass `urls.consent`? | **No** | Client has `skip_consent: true`; after login the browser still lands on `/consent?consent_challenge=...` and the consent request has `skip: false`. Source: `client.SkipConsent` is only read by dynamic-registration validation; the consent strategy never consults it (`skip` is only true for a remembered consent). Login needs a `/consent` that accepts. |
| 2 | Does `token_hook` fire on the refresh grant? | **Yes** | Hook request `request.grant_types: ["refresh_token"]`; the hook's `roles` replaced the old value in the refreshed JWT. `session.extra` carries the previous claims. (`oauth2.refresh_token_hook` is a separate, unused key.) |
| 3 | Does admin revocation by subject fire back-channel logout? | **No** | `DELETE /admin/oauth2/auth/sessions/login?subject=` and `.../consent?subject=&all=true` both 204, zero requests at the back-channel endpoint. The consent revoke does kill refresh tokens (`invalid_grant`); JWT access tokens stay valid until `exp`. hooks must call bff `/internal/revoke`. |
| 4 | Does Hydra accept an internal http `backchannel_logout_uri`? | **Yes** | Registered `http://weaveauth:8082/backchannel-logout`; delivered as `POST`, `application/x-www-form-urlencoded`, field `logout_token`. **The logout_token has `sid` but no `sub`** (claims: `aud events iat iss jti sid`): bff must store the id_token's `sid` per session and revoke by `sid`. |
| 5 | Does `oauth2_provider` cover registration, social sign-in and passkey flows from a `login_challenge`? | **Yes** | Login and registration flow objects carry `oauth2_login_challenge`; password, OIDC and passkey registration and login each ended with Hydra's login accepted (`login_verifier`) and, after the consent accept, tokens. A second `/oauth2/auth` in the same browser is accepted by Kratos with no UI. Passkeys were driven with a software WebAuthn authenticator (`amr: ["passkey"]`). |
| 6 | Does `require_verified_address` cover passkey and OIDC logins? | **Yes** | Unverified password, passkey and OIDC logins each started a verification flow and a code mail and did not accept Hydra's request; verified ones passed. Applies because `login.after.hooks` (global) is used when no method has its own list. Quirk: the code entered in a *login-started* verification flow ends on `/error` 404, address verified. |
| 7 | Do after-registration OIDC web hooks get provider tokens or granted scopes; when do they run relative to persistence? | **No tokens, no scopes; after persistence** | Context keys: `flow, identity, request_cookies, request_headers, request_method, request_url` (+ `session` for login/settings hooks). `flow.active` is `"oidc"` (the provider id is only in `request_url`, `.../callback/<id>`), identity has no `credentials`. A stub read `GET /admin/identities/{id}?include_credential=oidc` from inside the running hook: 200 with `initial_access_token`, `initial_refresh_token`, `initial_id_token`. Failing hook (400 with `messages`, or 500): browser on `/error` (502/500), **identity stays persisted**. With `response.parse`/`can_interrupt` the hook runs before persistence (source). So profile APIs work from the hook via Kratos admin, and a failure must delete the identity. |
| 8 | Does the client's `audience` end up in the JWT `aud`? | **No** | `aud: []` with `client.audience: [weaveauth]`. It is an allow-list (an `audience=` outside it is `invalid_request`). `aud: ["weaveauth"]` when either the authorize request has `audience=weaveauth` or `/consent` accepts with `grant_access_token_audience: <client.audience>`. |
| 9 | How should Hydra logout and Kratos logout be chained? | **Hydra drives; one hop is enough** | `GET /oauth2/sessions/logout?id_token_hint&post_logout_redirect_uri` -> `302 login /logout?logout_challenge=C` (even with a valid hint) -> login `PUT admin /oauth2/auth/requests/logout/accept?logout_challenge=C` -> `303 redirect_to` (Hydra's `logout_verifier` URL) -> Hydra sends the back-channel POST and `302`s to `post_logout_redirect_uri`. With `urls.identity_provider.url` set, Hydra also disables the Kratos session (401 on whoami afterwards), so login need not call Kratos. If login wants to clear the cookie it can chain `GET /self-service/logout/browser` (JSON, with the browser's cookies) then 303 to `logout_url&return_to=<redirect_to>` (accepted; also tested). **Refresh tokens survive logout**, bff must revoke its own. |

Further findings that change what the other services build (all in `run_checks.py`):

- **Token hook payload.** Request: `{"session": {...}, "request": {...}}`. `session.subject` and
  `session.id_token.subject` are the identity id; `session.id_token.id_token_claims` has `iss sub aud amr
  auth_time rat` and `ext.sid`; `session.extra` is the current access-token extra (previous claims on
  refresh); `session.client_id`; `request` has `client_id, requested_scopes, granted_scopes ([] on the code
  grant), granted_audience ([]), grant_types, payload` (the token request form with `assertion` removed).
  Response: `200 {"session":{"access_token":{...},"id_token":{...}}}` (replaces `extra` on both tokens; claims
  named in `allowed_top_level_claims` become top-level), `204` leaves them, `403` -> `access_denied` (403 at the
  token endpoint, no retry), anything else -> `server_error` (500 after Hydra retries 3 times, about 3 s). A
  failing hook leaves the refresh token usable afterwards; the grant fails closed.
  JWT access token claims: `aud client_id exp iat iss jti nbf scp sub` + the hook's claims.
- **Registration and the OAuth2 flow.** Without a `session` hook Kratos hands out no `login_verifier` at the end
  of registration (`run_checks.py json`), so the challenge waits for the verification. hooks' token hook is the
  second gate: with `require_verified_email`
  (default `true`) it answers `403` when the identity's address is unverified, so no token is issued. The
  overlay `session-on-registration.yml` and any deployment that wants unverified sign-in set it to `false`.
- **Sessions of the identity.** Every registration leaves an unissued Kratos session behind (active, no
  cookie); the recovery purge removes it.
- **Hydra's OAuth2 login CSRF cookie** is `SameSite=None; Secure` on the login host, fine for the redirect back
  from Google.
- **Courier/CA.** Mail reaches Mailpit over STARTTLS with verification. Without the local CA in the container
  the courier fails with `x509: certificate signed by unknown authority` (negative control). `SSL_CERT_DIR` adds
  the CA directory next to the system roots without replacing them, so Google still validates.
- **Egress.** Kratos on the `egress` network reaches Google: a login flow with the Google provider answers
  `303 https://accounts.google.com/o/oauth2/v2/auth?...redirect_uri=.../callback/google`.
- **Caddy routing.** `/self-service/*` and `/.well-known/ory/*` are answered by login only; `/oauth2/token`, the
  JWKS and `/admin/*` on the login host reach login, not Hydra; only `/oauth2/auth` and
  `/oauth2/sessions/logout` go to Hydra.
- **Hydra and the HTTP issuer.** The discovery document and JWKS are served on the internal plain-HTTP port
  with `https://login...` URLs inside. bff must not use discovery for endpoints.
- **Verified-first off (overlay).** Password registration signs in at once (`ory_kratos_session`), goes
  straight to consent and tokens; the verification mail is still sent and the unverified user logs in later.
- **Mails.** Subjects `Your verification code` and `Reset your password`, 6-digit codes, 60 minutes,
  `no-reply@weaveauth.localhost`; both parts (text and HTML) are rendered from `courier-templates/`.
