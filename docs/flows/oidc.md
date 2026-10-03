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

- bff asks backend (server-to-server) for the provider's consent-screen URL (`GET /oauth/oidc/login?provider=...`). The provider name travels as a query value, never in the backend URL path, so a crafted name can't steer the request at another backend route; an unknown name is backend's `404`.
- backend builds that URL via the `oauth2` crate, which generates the
  `state` CSRF token and PKCE verifier internally, and requests `openid`
  plus the provider's configured `scopes` (default `email`, `profile`). Backend stores
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
  (`GET /oauth/oidc/callback?provider=...&code=...&state=...`), plus
  `pending_link_token` when the browser carries the pending-link cookie (see step 2b). Backend:
  - looks up `state` in its own store (`take_state`, single-use) --
    this is the *second*, independent state check, done server-side
    against backend's own record rather than a cookie;
  - completes the PKCE code exchange and OIDC claims verification with the
    provider;
  - if the login is for a new user and the provider has `extra_claims`
    configured (`field name -> id_token claim name`) and/or `profile_apis`
    (GET calls made with the access token, each mapping `field name -> JSON
    pointer` into the response, called concurrently), hands those fields to
    the `extra_data_handler` as the registration fields, *before* the user
    is created (with the id it will get). A handler failure fails the
    callback (`502`) and no user is created, so the downstream service and
    WeaveAuth never disagree about whether the user exists. A profile API
    call that fails (request error, non-2xx, body that isn't JSON) is skipped
    with a warning unless that entry sets `required: true`, which fails the
    callback (`502`) the same way. A pointer that finds nothing just leaves
    that field out, silently, unless the entry is `required`. An entry with
    a `scope` is only called if the token response lists that scope as
    granted (no `scope` field means everything asked for was): when the user
    declined it, an optional entry is skipped without a call, and a
    `required` one fails the callback with `403` before any call is made,
    which bff turns into a redirect to `next?error=consent_required`;
  - resolves the identity: already linked -> that account; new email -> a new
    account with this identity linked; an existing account with this email
    -> link confirmation required.
- Two outcomes:
  - **Authenticated** -- `complete_login` runs (mirrors a password login),
    `wa_session` gets set, the 3 flow cookies get cleared, browser lands on
    `redirect_uri`.
  - **LinkConfirmationRequired** -- an account with this email exists and
    this identity isn't linked to it. A provider's verified email proves
    mailbox access, not ownership of the account (which could be a squatter's
    registration), so the user confirms the link with the account's password
    or a sign-in through a provider already linked to it. bff redirects to
    `next?email=...&provider=<key>&has_password=true|false[&linked_providers=google,...]`
    and sets a 4th cookie, the pending-link cookie: `__Host-wa_oidc_pending_link_token`
    with `Path=/` over HTTPS, so a sibling subdomain can't plant one (the prefix
    requires `Secure`, so plain-http dev uses `wa_oidc_pending_link_token` on
    `/oidc`); same TTL/HttpOnly as the flow cookies, but `SameSite=None`. The
    login page names the provider being linked ("link your LinkedIn sign-in",
    so an account owner who finds the prompt left open in a shared browser can
    see it isn't theirs), renders a password form if `has_password`, and a
    "Continue with" link per linked provider -- or, with neither, says the
    sign-in can't be linked there. Provider names come from
    backend's config (`display_name`, default the key capitalized), which
    login fetches server-side through bff's `/oidc/providers` (cached for 5
    minutes, so rendering the page, which anyone can do, doesn't hit bff each
    time) -- never from the URL -- and keys that list doesn't have are dropped, so a crafted link can't
    put its own text on the page. If the lookup fails, keys are shown as
    themselves, limited to `[A-Za-z0-9_-]`. The rest goes in the URL since it isn't sensitive; the token is
    half a credential so it goes in a cookie instead of the URL, where it'd
    otherwise land in browser history, the Referer of anything the login page
    loads, and any access log in front of it.

**2b. Confirming through a linked provider** -- the "Continue with" link starts
step 1 for that provider with `confirm_link=true`. Only then does
`start_oidc_login` keep the pending-link cookie; any other start clears it, so
a pending link left behind in a browser by someone who walked away from the
prompt can't turn a later sign-in started without `confirm_link` into a link
confirmation. `confirm_link=true` is only a query parameter -- anyone can put
it on a link -- so what stops a crafted link from confirming a *planted*
pending link is the `__Host-` cookie name, which sibling subdomains can't set
(over HTTPS only; see above). Step 2's callback forwards
`pending_link_token` to backend, which, before resolving anything:

- takes the pending link (single-use);
- requires the just-completed sign-in's `(provider, subject)` to be linked to
  the pending link's account -- otherwise, or when the pending link is unknown
  or expired, `409` and nothing is created or linked, which bff turns into
  `next?error=link_failed`;
- links the pending identity and returns `Authenticated`.

bff clears the pending-link cookie on every path of this callback.

`has_password` and `linked_providers` tell whoever holds a provider-verified
email for the account which ways in it has, and sit in the login page's URL
(browser history, access logs). Accepted: it's the minimum the page needs to
offer the right choices, and someone able to sign in to any of those providers
as the owner doesn't need the hint.

**3. `POST /oidc/confirm-link`** (bff: `oidc_confirm_link`) -- the
confirm-link password form's submit target.

- Checks trusted origin + safe `next`.
- Reads `pending_link_token` from the cookie set in step 2 (not from the
  form).
- Posts `{pending_link_token, password}` to backend
  (`POST /oauth/oidc/confirm-link`).
- Wrong password or dead (already single-used) token -> bounce to
  `next?error=link_failed`; the pending-link cookie gets cleared either
  way, since it's single-use regardless of outcome.
- `redirect_uri` not allowlisted on backend -> `400`, not a bounce: it is
  the caller's bad input, not a backend fault (same as `/login`).
- Success -> `complete_login`, `wa_session` set, pending-link cookie
  cleared, browser lands on `redirect_uri`.

## Cookie summary

| Cookie                       | Set by                                       | Cleared by                       | Purpose                                                              |
|------------------------------|----------------------------------------------|----------------------------------|----------------------------------------------------------------------|
| `wa_oidc_redirect_uri`       | `start_oidc_login`                           | `oidc_callback` (every path)     | post-success landing page                                            |
| `wa_oidc_next`               | `start_oidc_login`                           | `oidc_callback` (every path)     | post-failure landing page                                            |
| `wa_oidc_state`              | `start_oidc_login`                           | `oidc_callback` (every path)     | login-CSRF: binds callback to the browser that started the flow      |
| `__Host-wa_oidc_pending_link_token` (`wa_oidc_pending_link_token` without HTTPS) | `oidc_callback` (link-required path) | `oidc_confirm_link`, `oidc_callback` (every other path), `start_oidc_login` (without `confirm_link`) | carries the half-credential link token without putting it in the URL |
| `wa_session`                 | `complete_login` (either final success path) | --                               | the actual authenticated session                                     |

All flow-scoped cookies are cleared (`Max-Age=0`) on every terminal path of
the handler that owns them -- success, friendly error, or hard error -- so
nothing outlives its single use.
