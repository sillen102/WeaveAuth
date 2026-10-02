# Email verification flow

A password registration creates an account with `email_verified: false`. When backend
has an `email_handler`, registering also emails the address a 6-digit code. The user
types it on login's `verify-email.html`; that marks the account verified
(`email_verified: true` in every token issued afterwards). Verification spans all three
web services: `backend` (codes, sessions, delivery, state), `bff` (browser-facing POSTs,
cookies) and `login` (the page where the code is typed).

Relevant code:
- `backend/src/server/api/email_verification.rs` -- the request/confirm endpoints, the code
  hand-off to the handler, and the three handlers (SMTP, webhook, plugin)
- `backend/src/server/api/login.rs` -- hands out the `verification_session`
- `backend/src/server/api/register.rs` -- sends the first email after `create_user`
- `backend/src/storage/` -- `VerificationSessionStorage` and `EmailVerificationCodeStorage`
  (traits) with their in-memory implementations, `UserStorage::mark_email_verified_by_code`,
  the OIDC link guard
- `bff/src/server/verification.rs` -- the verification cookie and the redirect to the page
- `bff/src/server/api/verify_email.rs` -- `POST /verify-email` and `/verify-email/resend`
- `bff/src/server/api/login.rs`, `register.rs` -- where login and registration hand over to it
- `templates/emails/` -- the SMTP email templates; `templates/pages/verify-email.html` -- the page

## The verification session

The point of the design: **an account whose email isn't verified is never given a real
session when verification is required.** It is given a restricted credential that can do
exactly one thing, enter the code, and entering the right code is what releases the real
login. Nothing is checked per request, because the only way to a real session goes through
the code.

**1. Login (`POST /oauth/login`, backend).** The password is checked first, exactly as for
any login, so a wrong password is a plain `401` and nothing below reveals which accounts
exist. What comes back then depends on the account:

- *Verified:* `{login_session}`, as always.
- *Unverified, `require_verified_email: true`:* `{verification_session}` and **no
  `login_session`**. Without a `login_session` nothing can call `/oauth/authorize` or
  `/oauth/token`, so no access token is ever issued. Backend also sends the code email now
  (subject to the resend cooldown, so a user who has just registered isn't mailed twice).
- *Unverified, verification optional:* both `{login_session, verification_session}`. The user is
  logged in and may verify whenever they like.

The `verification_session` is a random 32-byte token held by backend's
`VerificationSessionStorage`, bound to one user and valid for
`email_verification_session_ttl_secs` (default 1800); the response also carries that lifetime
(`verification_session_ttl_secs`) so bff's cookie lives exactly as long. It is **not consumed** by
use, so a wrong code leaves it usable. It is only accepted by `/oauth/email-verification/*`.
A **password reset revokes every verification session of the account** and clears its code
state (see the limits below), like it revokes login sessions and refresh tokens: someone who
squatted the address before the real owner took the account back can't use a session from that
time afterwards, and can't have burned guesses just before the reset to lock the owner out.

**2. bff keeps it in a narrow cookie.** bff puts it in `wa_verify_session`: `HttpOnly`,
`Max-Age` = the lifetime backend reported, `Path=/verify-email` (so the browser only sends it to `/verify-email` and
`/verify-email/resend`), and cross-site capable (`SameSite=None; Secure` on https) because the
form that posts it lives on login's origin, like the OIDC pending-link cookie. The proxy only
looks at `wa_session`, so with just this cookie **every proxied route answers `401`**: that is
how the user stays boxed in. When verification is required bff sets no `wa_session` at all and
answers `303` to login's `verify-email.html?redirect_uri=<where they were going>` (placed next
to the `next` page the form came from). Registration's auto-login takes the same path, so a new
user lands on the code page and never in the app.

**3. The page.** `verify-email.html` has one field, the code (no password: the cookie already
proves who is signing in), and a "send a new code" button. It carries `redirect_uri` along.

**4. Entering the code (`POST /verify-email`, bff).** Form `{code, redirect_uri, next}`.

- `require_trusted_origin`, then `next` must be a same-origin path or a trusted origin
  (`is_safe_redirect_target`, `400` otherwise), then the shared per-IP auth rate limit.
- No `wa_verify_session` cookie: `303` to `next?status=session_expired` (the page then asks the
  user to sign in again, which issues a new session).
- Otherwise bff sends `{verification_session, code}` to backend's
  `POST /oauth/email-verification/confirm`. Backend finds the user for the session (`401` if
  unknown/expired -> `session_expired`, cookie cleared) and checks the code. A wrong, expired
  or used-up code is `400` -> `next?status=invalid`, and the session stays. Guessing is
  limited three ways, all kept **per user** and surviving a code being used up (otherwise "5 wrong
  guesses, resend, 5 more" would never be limited):
  - a code survives **5 wrong attempts**; the fifth deletes it;
  - a new code can't be issued within the resend cooldown of the last one, however the last one
    ended (spent by wrong guesses, used, or expired);
  - **10 wrong guesses in a row** across codes lock the user out for an hour: even the right code
    fails and no new code is issued or mailed until the lock ends. A right code resets the count,
    and so does a password reset.
- A right code marks the email verified (`email_verified_by_code`), **deletes the verification
  session** and returns the `login_session` the login withheld. If the account is *already*
  verified, the code isn't checked and **no login session is given**: the session is deleted and
  the request is `401`, so a session from before an account changed hands (see the password
  reset above) can never be turned into a login. bff immediately runs the normal PKCE login with
  the released session and `redirect_uri` (`complete_login`), sets the real `wa_session`, clears
  `wa_verify_session` and answers `303` to `redirect_uri`. The user typed their password once and
  the code once. A `redirect_uri` backend doesn't allowlist fails the login as usual (`400`).

**5. Resend (`POST /verify-email/resend`, bff).** Form `{next}`, same cookie and checks ->
backend's `POST /oauth/email-verification/request`, which answers `202` and sends only when the
account is unverified and outside the cooldown (`email_verification_resend_cooldown_secs`,
default 60). bff bounces to `next?status=sent` in every accepted case.

**Other cases**
- OIDC accounts are already verified and never see any of this.
- A service calling backend's `/oauth/login` directly gets no `login_session` for an unverified
  account either, so it can't obtain tokens for one.
- The verification session expiring (or the cookie vanishing) is harmless: signing in again
  issues a new one.

## Sending the code

Backend's `send_verification_email`, called by `register`, by login (when verification is
required) and by the resend endpoint.

- No `email_handler` configured: nothing happens and no code is issued.
- A code is issued for the user: 6 random digits, stored only as a sha256 over the user id and
  the code, valid for `email_verification_code_ttl_secs` (default 900). A new code replaces the
  old one. A second code is **not** issued within `email_verification_resend_cooldown_secs` of the
  last one, so resend can't flood an inbox or keep replacing the code the user is typing.
- The handler gets `{user_id, email, code, verify_page_url, expires_at}` (`expires_at` is RFC
  3339, UTC) and runs in a **background task**, so neither registration, login nor the resend
  response waits for SMTP or the plugin, and response time can't show which requests send mail:
  - `smtp` renders `templates/emails/verify-email.{subject.txt,txt,html}` and sends a multipart
    message. Templates load at startup; a missing one fails boot. `tls: none` is refused for a
    non-loopback host, because the code and any credentials would cross the network in the clear.
  - `webhook` POSTs that payload as JSON (https unless loopback, no redirects, timeout).
  - `plugin` calls the plugin with `hook: "email_verification"` ([plugins](../plugins.md)).
- A delivery failure is logged (in the task) and nowhere else: the account already exists and
  the user can ask for a new code.

## Requiring verification

`require_verified_email: true` is what withholds the `login_session` (step 1). It is read by
backend only; bff just follows what `/oauth/login` returns, so there is one setting and one
place that enforces it.

## Interaction with OIDC linking

Entering the code sets `email_verified_by_code`. `resolve_oidc_login` still asks such an account
for its password before linking a Google (etc.) identity, exactly as for an unverified one: the
code proves mailbox access to whoever chose the password, not that a provider vouches for the
address, and without this an attacker who pre-registered a victim's address could ride the
victim's own verification into a shared account. Confirming the password in
`/oauth/oidc/confirm-link` clears the flag.

## Known gaps

- Codes and verification sessions live in memory behind storage traits, like the other
  single-use secrets; a restart drops them (the user signs in again and asks for a new code).
  A durable implementation is a new impl of the same traits.
- The `wa_verify_session` cookie must reach bff from the login page's form. It is cross-site
  capable on https; on plain http, login and bff have to be same-site (as in local dev).
- There is no rate limit on backend's endpoints themselves, only on bff's per IP; the per-user
  limits are the 5-attempt cap, the resend cooldown and the hour-long lockout after 10 wrong
  guesses (constants in `storage/in_memory.rs`, not configurable yet).
- A completed password reset does not verify the address yet (see `TODO.md`).
