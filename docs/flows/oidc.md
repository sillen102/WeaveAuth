# OIDC login flow

Third-party login (Google, etc.) spans two services: `bff` (internet-facing,
talks to the browser) and `backend` (not internet-exposed, talks to the OIDC
provider and owns user data). `bff` never talks to the provider directly --
everything provider-facing is proxied server-to-server through `backend`.

Relevant code:
- `bff/src/server/api/oidc.rs` -- browser-facing endpoints, cookie handling
- `backend/src/server/api/oidc.rs` -- provider exchange, PKCE, user resolution

## Steps

**1. `GET /oidc/{provider}/login`** (bff: `start_oidc_login`)

Browser lands here to start login (`redirect_uri` = where to go after
success, `next` = where to go after failure -- both validated as
same-origin/trusted before use).

- bff asks backend (server-to-server) for the provider's consent-screen URL.
- backend builds that URL via the `oauth2` crate, which generates the
  `state` CSRF token and PKCE verifier internally. Backend stores
  `state -> {provider, pkce_verifier, nonce}` server-side
  (`oidc_state.save_state`) and returns the authorize URL in a redirect.
- bff pulls `state` back out of that URL's query string and redirects the
  browser to the provider, setting 3 cookies (path `/oidc`, 300s TTL,
  HttpOnly, `SameSite=Lax`):

  | Cookie                 | Holds                                                                   |
  |------------------------|-------------------------------------------------------------------------|
  | `wa_oidc_redirect_uri` | where to land on success                                                |
  | `wa_oidc_next`         | where to bounce on failure                                              |
  | `wa_oidc_state`        | the `state` value, so the callback can confirm this is the same browser |

**2. `GET /oidc/{provider}/callback`** (bff: `oidc_callback`) -- provider
redirects the browser here with `code` + `state`.

- Reads the 3 cookies above. Any missing -> `MissingFlowState`; all 3 get
  cleared before returning, so a half-finished flow doesn't linger for the
  rest of the 300s TTL and get reused by a retried callback.
- Compares the `state` query param to the `wa_oidc_state` cookie
  (`StateMismatch` on mismatch, cookies cleared the same way). This is the
  browser-binding check -- it doesn't require constant-time comparison,
  since `state` isn't a secret the attacker lacks, just proof this browser
  started the flow (login-CSRF defense).
- Forwards `code`/`state` to backend server-to-server
  (`POST .../oauth/oidc/{provider}/callback`). Backend:
  - looks up `state` in its own store (`take_state`, single-use) --
    this is the *second*, independent state check, done server-side
    against backend's own record rather than a cookie;
  - completes the PKCE code exchange and OIDC claims verification with the
    provider;
  - resolves the verified email against existing users.
- Two outcomes:
  - **Authenticated** -- `complete_login` runs (mirrors a password login),
    `wa_session` gets set, the 3 flow cookies get cleared, browser lands on
    `redirect_uri`.
  - **PasswordConfirmationRequired** -- the email matches an existing,
    unverified account; the login page needs to show a "confirm your
    password to link this account" form. bff redirects to
    `next?email=...` and sets a 4th cookie, `wa_oidc_pending_link_token`
    (same path/TTL/HttpOnly shape as the flow cookies). `email` alone goes
    in the URL since it isn't sensitive; the token is half a credential
    (paired with the account password) so it goes in a cookie instead of
    the URL, where it'd otherwise land in browser history, the Referer of
    anything the login page loads, and any access log in front of it.

**3. `POST /oidc/confirm-link`** (bff: `oidc_confirm_link`) -- the
confirm-link form's submit target.

- Checks trusted origin + safe `next`.
- Reads `pending_link_token` from the cookie set in step 2 (not from the
  form).
- Posts `{pending_link_token, password}` to backend
  (`POST /oauth/oidc/confirm-link`).
- Wrong password or dead (already single-used) token -> bounce to
  `next?error=link_failed`; the pending-link cookie gets cleared either
  way, since it's single-use regardless of outcome.
- Success -> `complete_login`, `wa_session` set, pending-link cookie
  cleared, browser lands on `redirect_uri`.

## Cookie summary

| Cookie                       | Set by                                       | Cleared by                       | Purpose                                                              |
|------------------------------|----------------------------------------------|----------------------------------|----------------------------------------------------------------------|
| `wa_oidc_redirect_uri`       | `start_oidc_login`                           | `oidc_callback` (every path)     | post-success landing page                                            |
| `wa_oidc_next`               | `start_oidc_login`                           | `oidc_callback` (every path)     | post-failure landing page                                            |
| `wa_oidc_state`              | `start_oidc_login`                           | `oidc_callback` (every path)     | login-CSRF: binds callback to the browser that started the flow      |
| `wa_oidc_pending_link_token` | `oidc_callback` (link-required path)         | `oidc_confirm_link` (every path) | carries the half-credential link token without putting it in the URL |
| `wa_session`                 | `complete_login` (either final success path) | --                               | the actual authenticated session                                     |

All flow-scoped cookies are cleared (`Max-Age=0`) on every terminal path of
the handler that owns them -- success, friendly error, or hard error -- so
nothing outlives its single use.
