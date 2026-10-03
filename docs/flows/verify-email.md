# Email verification flow

A password registration creates an account with `email_verified: false`. When backend
has an `email_handler`, registering also emails the address a 9-digit code. The user
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
  (traits) with their in-memory implementations, `UserStorage::mark_email_verified`,
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
  `/oauth/token`, so no access token is ever issued. Backend also sends a code, unless the
  account already holds a live one (so a user who has just registered isn't mailed twice).
- *Unverified, verification optional:* both `{login_session, verification_session}`. The user is
  logged in and may verify whenever they like. Login sends no email here; offering a "verify my
  email" button that calls the resend endpoint is up to the deployer.

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
`Max-Age` = the lifetime backend reported, `Path=/verify-email` (so the browser only sends it
to `/verify-email` and `/verify-email/resend`), and cross-site capable (`SameSite=None; Secure`
on https) because the form that posts it lives on login's origin, like the OIDC pending-link
cookie. The proxy only looks at `wa_session`, so with just this cookie **every proxied route
answers `401`**: that is how the user stays boxed in. When verification is required bff sets no
`wa_session` at all and answers `303` to login's
`verify-email.html?redirect_uri=<where they were going>` (placed next to the `next` page the form
came from). Registration's auto-login takes the same path, so a new user lands on the code page
and never in the app.

**3. The page.** `verify-email.html` has one field, the code (no password: the cookie already
proves who is signing in), and a "send a new code" button. It carries `redirect_uri` along. Opened
without one (the link in the email), it uses login's `WA_VERIFY_DEFAULT_REDIRECT_URI`, else login's
own origin; backend's allowlist must include whichever applies.

**4. Entering the code (`POST /verify-email`, bff).** Form `{code, redirect_uri, next}`.

- `require_trusted_origin`, then `next` must be a same-origin path or a trusted origin
  (`is_safe_redirect_target`, `400` otherwise), then the shared per-IP auth rate limit.
- No `wa_verify_session` cookie: `303` to `next?status=session_expired` (the page then asks the
  user to sign in again, which issues a new session).
- Otherwise bff sends `{verification_session, code}` to backend's
  `POST /oauth/email-verification/confirm`. Backend finds the user for the session (`401` if
  unknown/expired -> `session_expired`, cookie cleared) and checks the code. A wrong, expired
  code is `400` -> `next?status=invalid`, and the session stays; a code deleted by its fifth
  wrong attempt is `400` with reason `CodeUsedUp` -> `next?status=code_used_up` ("ask for a new
  one"). Guessing is limited per user (see [Guessing limits and the
  lockout](#guessing-limits-and-the-lockout)). While the user is locked out, backend answers
  `423` instead of `400`, with `{status: "locked", retry_after_secs}` or
  `{status: "locked_until_reset"}` -> bff clears `wa_verify_session` and bounces to
  `next?status=locked&retry_after=<secs>` or `next?status=locked_until_reset`. The page shows no
  forms. For `locked` it offers a "Sign in" link (a lock outlasts the verification session); for
  `locked_until_reset` signing in can't help, so it only says to reset the password (see Known
  gaps).
- A right code marks the email verified, **deletes the verification
  session** and returns the `login_session` the login withheld. If the account is *already*
  verified, the code isn't checked and **no login session is given**: the session is deleted and
  the request is `401`, so a session from before an account changed hands (see the password
  reset above) can never be turned into a login. bff immediately runs the normal PKCE login with
  the released session and `redirect_uri` (`complete_login`), sets the real `wa_session`, clears
  `wa_verify_session` and answers `303` to `redirect_uri`. The user typed their password once and
  the code once. A `redirect_uri` backend doesn't allowlist fails the login as usual (`400`).

**5. Resend (`POST /verify-email/resend`, bff).** Form `{next}`, same cookie and checks ->
backend's `POST /oauth/email-verification/request`, which sends only when the account is
unverified, outside the cooldown (`email_verification_resend_cooldown_secs`, default 60) and not
locked out, and says which happened:
- sent: `202 {status: "sent", expires_in_secs}` -> bff bounces to
  `next?status=sent&expires_in=<secs>` and the page says how long the code is valid;
- inside the cooldown: `202 {status: "cooling_down", retry_after_secs}` -> bff bounces to
  `next?status=cooling_down&retry_after=<secs>`;
- locked out after wrong guesses: `202 {status: "locked", retry_after_secs}` -> bff bounces to
  `next?status=locked&retry_after=<secs>` and clears `wa_verify_session` (the lock outlasts the
  session, which is useless meanwhile). The page shows no forms, since even the right code is
  rejected until the lock ends, only a "Sign in" link;
- locked out five times: `202 {status: "locked_until_reset"}` -> bff clears the cookie and
  bounces to `next?status=locked_until_reset`;
- account already verified or session unknown: `401` -> `session_expired`;
- no email handler configured: `503` -> bff answers `502`.

The page tells the user how long to wait, in seconds under two minutes and in minutes (rounded
up) from there: for `cooling_down` until "Send a new code" will work, for `locked` until signing
in again will. A `cooling_down` wait under two minutes counts down on the page
(`login/static/countdown.js`, loaded only for that status, the page's one script) and shows "You
can ask for another one now" at zero. Without JavaScript the page shows the starting number as
plain text. The server doesn't send the page again, so the count runs from when the page loaded
(the browser's clock doesn't matter; the only drift is the time between backend working out the
wait and the page loading, which the rounding up covers).

**Other cases**
- OIDC accounts are already verified and never see any of this.
- A service calling backend's `/oauth/login` directly gets no `login_session` for an unverified
  account either, so it can't obtain tokens for one.
- The verification session expiring (or the cookie vanishing) is harmless: signing in again
  issues a new one.

## Guessing limits and the lockout

**What it protects.** A verified email is a claim of owning that inbox, and OIDC login matches
accounts by verified email. Someone who registers with a victim's address knows the password
(they chose it), so they can always get a verification session; the code is the only thing
between them and a verified account they could later use against the victim's own OIDC login. A
9-digit code is a 1-in-10^9 guess, so the limits below are about making online guessing hopeless,
not merely slow.

**The limits.** All live in `UserCodes` (`storage/in_memory.rs`), kept **per user** rather than
per code, IP or session: a code being used up doesn't reset them, rotating IPs doesn't get round
bff's per-IP rate limit, and signing in again for a fresh verification session doesn't help.

- A code survives **5 wrong attempts**; the fifth deletes it (`code_used_up`).
- A new code isn't issued within the **resend cooldown** of the last one (default 60s), however
  the last one ended. Without it, "5 guesses, resend, 5 more" would run unchecked.
- **10 wrong guesses in a row** (across codes) **lock the user out**:
  - Even the right code is refused, without being compared. If it were accepted, the lock would
    only slow guessing: the attacker could keep going until the right guess got in.
  - No new code is issued or mailed, so the lock can't be used to flood the inbox either.
  - Each lock starts a fresh count for the next one.

**Escalation.** A lock is remembered for a day after it ends, and each lock that starts while
the previous one is remembered lasts twice as long: 1h, 2h, 4h, 8h, 16h. The lock after the fifth
lasts **until a password reset**. A day without a lock forgets the escalation; a right code resets
both the count and the escalation.

**How a lock ends.** It runs out, or a password reset clears all of the user's code state (the
only way out of the last lock). The reset link goes to the inbox, so whoever squatted the address
can't lift a lock that way. (Reset emails aren't delivered yet: see Known gaps.)

**Who can trigger it.** Guessing needs a verification session, which needs the account's
password, so nobody can lock a stranger out; at worst a squatter locks their own account. The
reset clears a squatter's lock and failure count before the real owner takes over.

**What it adds up to.** An attacker who paces themselves to never reach the reset lock gets about
50 guesses per 55 hours (the five locks plus the day it takes to forget them), roughly 8,000 a
year: under 1-in-100,000 odds of hitting one address's code in a year.

## Sending the code

Backend's `send_verification_email`, called by `register` (always), by login (only when
verification is required and the account has no live code) and by the resend endpoint.

- No `email_handler` configured: nothing happens and no code is issued.
- A code is issued for the user: 9 random digits, stored only as a sha256 over the user id and
  the code, valid for `email_verification_code_ttl_secs` (default 900). A new code replaces the
  old one. A second code is **not** issued within `email_verification_resend_cooldown_secs` of the
  last one, so resend can't flood an inbox or keep replacing the code the user is typing.
- The handler gets `{user_id, email, code, verify_page_url, expires_at}` (`expires_at` is RFC
  3339, UTC) and runs in a **background task**, so neither registration, login nor the resend
  response waits for SMTP or the plugin. For registration and login, response time can't show
  which requests send mail (the resend response says outright whether it sent):
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

Verification doesn't change OIDC linking: `resolve_oidc_login` asks every existing account to
confirm a new identity, verified or not (see [oidc.md](oidc.md)). The code proves mailbox access
to whoever chose the password, so without that an attacker who pre-registered a victim's address
could ride the victim's own verification into a shared account.

## Known gaps

- Codes and verification sessions live in memory behind storage traits, like the other
  single-use secrets; a restart drops them (the user signs in again and asks for a new code).
  A durable implementation is a new impl of the same traits.
- The `wa_verify_session` cookie must reach bff from the login page's form. It is cross-site
  capable on https; on plain http, login and bff have to be same-site (as in local dev).
- There is no rate limit on backend's endpoints themselves, only on bff's per IP; the per-user
  limits are the 5-attempt cap, the resend cooldown and the escalating lockout after 10 wrong
  guesses (constants in `storage/in_memory.rs`, not configurable yet).
- A completed password reset does not verify the address yet (see `TODO.md`).
- Password reset has no email delivery yet ([password-reset](password-reset.md)), so a user in
  the lock that lasts until a reset has no way out until it does, short of a backend restart (the
  lock lives in memory). The hard-lock page tells them to reset their password; once reset emails
  exist it should link to the reset page.
