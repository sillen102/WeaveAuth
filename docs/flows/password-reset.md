# Password reset flow

A user who can't sign in asks for a reset link by email, opens it, and chooses a
new password. This is also how the real owner of an address takes an account
back from someone who registered it first: confirming an OIDC link needs the
account's current password (see [OIDC](oidc.md)), and a reset gives them one.

Pages live in `login`, the browser-facing routes in `bff`, and the work in
`backend`:

- `templates/pages/forgot-password.html`, `templates/pages/reset-password.html`,
  `login/static/reset-password.js`
- `bff/src/server/api/password_reset.rs` -- `/password-reset/request`, `/password-reset/confirm`
- `backend/src/server/api/password_reset.rs` -- `/oauth/password-reset/request`, `/oauth/password-reset/confirm`
- `backend/src/email.rs` -- delivery, shared with [verify email](verify-email.md)
- `backend/src/storage/in_memory.rs` -- `InMemoryPasswordResetTokenStorage`

## Steps

**1. Ask for a link.** `forgot-password.html` (linked from the login form, from
the link-confirm view next to its password field, and from the verification
page once the account is locked until a reset) posts `email` to bff's
`POST /password-reset/request`. bff checks the `Origin`, forwards
`{"email"}` to backend and always answers with a 303 to
`forgot-password.html?status=sent` ("if an account uses that address, a link is
on its way"). It answers 502 only if backend is unreachable, which says nothing
about any account.

**2. Backend issues and mails the token.** `POST /oauth/password-reset/request`
always answers **202**. It looks the address up with `normalize_email`, then
mails nothing when:

- no account matches,
- no email handler is configured (backend warns about that once at startup), or
- the account got a token less than `password_reset_resend_cooldown_secs` (60s)
  ago.

Otherwise `issue_reset_token` mints 32 CSPRNG bytes, base64url, and stores
`sha256(token) -> (user_id, issued_at)`. The user's earlier tokens stay valid
until one of them is redeemed (see below). The mail goes in a background task to the
**account's stored address**, never to the request's input: `Alice+x@Example.com`
finds `alice@example.com`'s account, and the link goes to `alice@example.com`.
The link is

```
{login_public_url}/reset-password.html#token=<token>
```

The token is in the **fragment**, which browsers never send to a server or in a
`Referer`. The response is the same whether or not an account exists or a mail
went out, and the mail is sent in the background so SMTP or the plugin adds no
delay. This is not a timing-proof guarantee: a known address still costs a token
lookup and a hash more than an unknown one, and backend's own logs name the
account on the cooldown path. `/register` answers `409` for a taken address anyway,
so this endpoint isn't the easiest way to find out who has an account.

**3. Open the link.** login serves `reset-password.html` with
`Referrer-Policy: strict-origin` and `Cache-Control: no-store`. Not
`no-referrer`: under it the browser sends `Origin: null` on the form's POST,
which bff refuses; and no policy ever puts the fragment in a `Referer`. Its
script copies the token from the fragment into a hidden form field and into the
tab's `sessionStorage`, and removes the fragment from the address bar with
`history.replaceState`. On a reload, or after a rejected password, the field is
filled from `sessionStorage` again. The form starts hidden and the script shows
it only once it has a token. Without one, the script shows "open the link from
your email again" instead (a `<noscript>` copy covers a browser without JS), so
the user isn't sent to a submit that would fail as an expired link. The two
pages a reset ends on (`login.html?status=password_reset`,
`forgot-password.html?status=invalid_token`) remove the token from
`sessionStorage`. Opening the page changes nothing, so a mail scanner that
follows links can't spend the token.

**4. Submit the new password.** The form posts `token` and `new_password` to
bff's `POST /password-reset/confirm`. bff checks the `Origin`, refuses a token
that isn't 1-128 base64url characters without calling backend, forwards the
rest, and redirects:

| Backend answer           | bff redirects to                                         |
|--------------------------|----------------------------------------------------------|
| 200 `{user_id}`          | `login.html?status=password_reset`, after dropping every bff session of `user_id` |
| 400 `WeakPassword`       | `reset-password.html?status=weak_password` (no token; the page still has it) |
| other 400, bad token     | `forgot-password.html?status=invalid_token`              |
| anything else            | 502                                                      |

The user is **not** signed in: they sign in with the new password next. A forged
confirm therefore can't drop someone into an account that isn't theirs. Every
redirect goes to a fixed page on `login_public_url`; nothing from the request
picks the destination. Neither the reset link nor these redirects carry a
`redirect_uri`, so the login page reached with `status=password_reset` and
`forgot-password.html` use `WA_EMAIL_LINK_DEFAULT_REDIRECT_URI`, like the
verification page, else login's own origin.

**5. Backend redeems the token.** `POST /oauth/password-reset/confirm`:

1. `validate_new_password` (at least 8 characters, at most 1024 bytes; the same
   rule as `/register`). Failure is a 400 `WeakPassword`, and the token is still
   good, because this check runs before the token is touched.
2. `take_reset_token` removes the entry. Unknown, used, or older than
   `password_reset_token_ttl_secs` (30 minutes) gives a 400 `InvalidOrExpiredToken`.
   A good token also spends every other token the user still holds.
3. Argon2 hash on `spawn_blocking`.
4. `set_password`, which also bumps the user's `credential_version`.
5. `mark_email_verified`: redeeming the token proves control of the mailbox.
6. Clean-up: revoke the user's refresh tokens, login sessions and verification
   sessions, and clear their verification-code state (code, cooldown, failure
   count, lockout). A failure here is logged and the reset still succeeds:
   the password is already changed, and the stale credentials are refused anyway
   (below).
7. Answer `200 {"user_id"}`, so bff can end that user's sessions.

## Every earlier credential dies

Login sessions, authorization codes, refresh tokens and verification sessions
each carry a `CredentialStamp`: the user id plus the `credential_version` the
user had when the password (or provider sign-in) behind it was checked. Every
place that redeems one first calls `current_user`, which refuses the stamp once
the version has moved on:

- `/oauth/authorize` refuses a login session (`InvalidLoginSession`),
- `/oauth/token` refuses a code (`InvalidCode`) or refresh token (`InvalidRefreshToken`),
- the email-verification endpoints refuse a verification session (`InvalidSession`).

The stamp comes from the same snapshot of the user whose password was checked,
so timing doesn't matter. A login that checked the old password while the reset
ran, or a refresh rotation in flight, issues a credential with the old version,
and that credential is refused the first time it's used. A rotated refresh token
keeps its predecessor's stamp, so a token family started before the reset can't
renew itself into a valid one.

Two writes that come out of an old proof are refused the same way:

- **Upgrading a bcrypt hash** (`upgrade_password_hash`) writes only while the
  version still matches. Otherwise a login re-hashing the *old* password could
  overwrite the new one.
- **Linking an OIDC identity** (`link_verified_oidc_identity`) after a confirm-link
  password check writes only while the version still matches. A link outlives
  any session, so one approved by the old password must not land afterwards.

Access tokens never reach the browser: bff holds them, keyed by the session
cookie. On a done reset bff drops every one of the user's sessions
(`SessionStorage::revoke_all_for_user`), so the access tokens it held stop being
used at once, on every device. This relies on resets coming in through bff, which
holds because backend is never public. A trusted internal service that calls
backend's confirm itself has to do the same with the returned `user_id`.

## Token summary

| Property       | Value                                                        |
|----------------|--------------------------------------------------------------|
| Entropy        | 32 bytes CSPRNG (`rand::rng()`), base64url, no padding       |
| At rest        | `sha256(token)` as the map key; the token itself never stored|
| TTL            | `Tuning.password_reset_token_ttl_secs`, 30 minutes           |
| Reuse          | Single-use; a rejected password doesn't spend it             |
| Per user       | Several live tokens (at most TTL / cooldown); redeeming one spends all |
| Issuing        | At most one per `password_reset_resend_cooldown_secs` (60s)  |
| Transport      | URL fragment of login's reset page; then a form field and the tab's `sessionStorage` |
| Expiry cleanup | `sweep_expired`, run by the background task in `AppState`    |
| Exposure       | Never in a response, a header or a log line; only the mail, its handler, and the resetting tab's `sessionStorage` until the reset ends |

Unsalted SHA-256 is fine here: the input is 256 bits of CSPRNG output, so there
is nothing to brute-force, and the lookup has to be deterministic.

The cooldown is per user and silent. bff's per-IP rate limit covers both routes
(the auth bucket). An attacker can still mail the owner a fresh link once a
minute, but that doesn't invalidate the link the owner already has: every link
stays good until it expires or the owner redeems one. A leaked older link is no
worse than a leaked newer one, since all of them went to the same inbox.

## Delivery

Reset mails go through the same handler as verification codes (`email_handler`:
SMTP, webhook or plugin; see [verify email](verify-email.md#sending-the-code)):

- **SMTP** renders `templates/emails/password-reset.{subject.txt,txt,html}` with
  `email`, `reset_url` and `expires_at`. Backend refuses to start if any of them
  is missing.
- **Webhook** gets `{"kind": "password_reset", "user_id", "email", "reset_url",
  "expires_at"}`.
- **Plugin** gets hook `password_reset` with `data` `{reset_url, expires_at}`
  (see [plugins](../plugins.md)).

Whoever delivers the mail sees the link, the same as with verification codes.
