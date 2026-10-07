# Logout and back-channel logout

Logging out has to end four things: bff's session (the `wa_session` cookie and the tokens behind
it), the refresh token at Hydra, Hydra's login session and Kratos' session. bff starts it, Hydra
drives it, `login` ends the Kratos session, and Hydra then tells bff by back-channel so that every
bff session of the login session ends too.

Relevant code:
- `bff/src/server/api/logout.rs`, `logged_out.rs` -- the browser-facing ends
- `bff/src/server/api/backchannel_logout.rs`, `bff/src/hydra/logout_token.rs` -- the
  back-channel receiver and the `logout_token` checks
- `bff/src/server/api/internal_revoke.rs` -- the by-user revocation hooks uses
- `login/src/challenges.rs` -- `/logout`
- `ory/hydra/init-bff-client.sh` -- the client's `backchannel_logout_uri` and post-logout URI

```mermaid
sequenceDiagram
    autonumber
    actor U as Browser
    participant F as bff
    participant H as Hydra
    participant L as login
    participant K as Kratos

    U->>F: POST /logout?redirect_uri=R (Origin: a trusted origin, wa_session cookie)
    Note over F: 403 if the origin is not trusted; an R off the allowlist is dropped
    F->>H: revoke the session's refresh token
    F-->>U: 303 Hydra /oauth2/sessions/logout?id_token_hint&post_logout_redirect_uri=bff/logged-out&state=R<br/>+ wa_session cleared
    U->>H: GET /oauth2/sessions/logout
    H-->>U: 302 login /logout?logout_challenge=C
    U->>L: GET /logout?logout_challenge=C
    L->>H: look up C (admin API), must be a logout the app started (rp_initiated)
    L->>K: end the browser's Kratos session (cookie passed through)
    L->>H: accept C (admin API)
    L-->>U: 303 Hydra + the cookies Kratos cleared
    U->>H: GET
    H->>F: POST /backchannel-logout (logout_token) on the internal listener
    F-->>H: 200
    H-->>U: 302 bff /logged-out?state=R
    U->>F: GET /logged-out?state=R
    F-->>U: 303 R
```

## Steps

**1. `POST /logout[?redirect_uri=R]`** (bff: `logout`). A `POST` from a trusted origin only: the
session cookie rides along on any same-site request, so otherwise any site could sign users out.
`Origin` (falling back to `Referer`) must be in `WA_TRUSTED_ORIGINS` or bff's own origin (`403`).
`R` is optional and is only used when it is on the allowlist: any other is dropped (logged), and the
logout goes on without it, since a logout must not fail and leave the user signed in.

- The session named by the cookie is removed from bff's store and its refresh token revoked at
  Hydra. If that revocation fails it is logged and the logout goes on (the token ends with its TTL).
- The cookie is cleared and the browser gets `303` to Hydra's `oauth2/sessions/logout` with the
  session's `id_token` as `id_token_hint`, bff's `/logged-out` as `post_logout_redirect_uri` and
  `R` as `state` (when allowed). The hint is what lets Hydra skip its own confirmation page.
- Hydra only returns the browser to a path on bff's origin (the client's registered post-logout
  URI), which is why the application's destination travels as `state`.

**2. Hydra to `login`.** Hydra redirects to `login`'s `/logout?logout_challenge=C`. `login` looks
the challenge up and acts only on one the application started (Hydra reports `rp_initiated`, which it does
when the `id_token_hint` was valid); a bare link to Hydra's logout endpoint, or a logout with no
session at bff behind it, ends on an error page (`400`, "Sign out from the application you are signed
in to") instead of signing anyone out. For an accepted challenge `login` asks Kratos to end the
browser's session (a failure is logged and does not stop the logout), accepts Hydra's request and
passes Kratos' cleared cookies on to the browser.

**3. Back-channel logout: `POST /backchannel-logout`** (bff internal listener, form field
`logout_token`). Once the logout is accepted Hydra posts a `logout_token` to the client's
`backchannel_logout_uri`. The listener is never routed publicly; the token itself is the
authorization:

- signature against Hydra's JWKS (RS256 only; the keys are cached, refetched on an unknown
  `kid` (at most once every 10 seconds) and once they are an hour old, so a key Hydra removed stops verifying), `iss` Hydra's issuer, `aud` bff's client id, `iat` within
  ten minutes (and not in the future), `exp` when present, the back-channel logout `events` member,
  **no** `nonce`, a `jti`, and a `sub` or a `sid`. Invalid is `400`; Hydra's signing keys
  unreachable is `503` (Hydra retries).
- the `jti` is remembered until the token could no longer pass the age check, so a replay is `400`.
  Only a verified token's `jti` is remembered.
- which sessions end depends on the claims. Hydra's token carries a `sid` and no `sub`, so in
  practice: a `sid` alone ends the bff session whose id_token had that `sid`. A token with `sub` and
  `sid` ends that session and any of that user's sessions with no stored `sid`; a token with only
  `sub` ends every session of the user.
- ending a session drops it from bff's store, and revokes its refresh token at Hydra.
- the answer is `200`, also when no session matched, with `Cache-Control: no-store`.

For the browser that logged out in step 1 the session is already gone. The back-channel is what ends
the *other* bff sessions of the same Hydra login session (another browser tab's cookie, say).

**4. `GET /logged-out?state=R`** (bff). Where Hydra sends the browser last. Anyone can send a
browser here with any `state`, so `state` is followed only if it is on the allowlist; otherwise
bff sends the browser to `WA_DEFAULT_REDIRECT_URI`, and without one it answers `400`.

## Ending sessions without a logout

Hydra's admin revocation by subject (what hooks does after a recovery or a password change) does
not fire back-channel logout. So hooks also calls bff's internal `POST /internal/revoke {sub}`
(`Authorization: Bearer <WA_BFF_INTERNAL_API_KEY>`, `204`, `401` without the key), which ends every
bff session of that user the same way: removed from the store, refresh token revoked at Hydra. See
[recovery.md](recovery.md). JWT access tokens issued before stay valid until `exp`.
