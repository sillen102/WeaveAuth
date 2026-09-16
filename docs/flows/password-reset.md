# Password reset flow

Two `backend` endpoints: request a reset token for an email, then redeem it to
set a new password. Unlike the [OIDC flow](oidc.md), there is no `bff` half --
nothing browser-facing, no cookies, no redirects. Both endpoints take and
return JSON.

**There is no email delivery yet**, and the token only ever exists in storage
and in `/request`'s own stack frame. Nothing can retrieve it, so the flow can't
be completed end-to-end. The contract exists so `/confirm` is settled before a
delivery channel lands.

Relevant code:
- `backend/src/server/api/password_reset.rs` -- both handlers
- `backend/src/storage/in_memory.rs` -- `InMemoryPasswordResetTokenStorage`
- `backend/src/storage/mod.rs` -- `PasswordResetTokenStorage` contract

## Steps

**1. `POST /oauth/password-reset/request`** (`request_password_reset`)

Body: `{"email": "..."}`. Always responds **202 Accepted**.

- Email is normalized (`normalize_email`) before lookup, so casing and `+tag`
  variants hit the same account they registered under.
- On a match, `save_reset_token` mints 32 bytes from the CSPRNG, base64url
  encodes them, and stores `sha256(token) -> (user_id, issued_at)`.
- On no match, nothing happens.

Three properties this endpoint holds deliberately:

- **Same response either way.** A 404 for an unknown email would be an
  account-existence oracle, the same concern `/oauth/login`'s
  `DUMMY_PASSWORD_HASH` exists to close off.
- **Stored hashed, not plaintext.** A table of directly-usable reset tokens
  makes one read of that table an account takeover for every pending reset.
  The trait contract is what a durable (e.g. Postgres) implementation follows
  too, so the hashing lives in the storage layer rather than the handler.
- **A new request supersedes the old one.** Issuing drops any existing token
  for that user, so only the newest link is live. Otherwise every unexpired
  token stays independently redeemable -- widening the window a leaked link
  stays dangerous, and letting an unauthenticated caller grow the table
  without bound by re-requesting the same address.

**2. `POST /oauth/password-reset/confirm`** (`confirm_password_reset`)

Body: `{"token": "...", "new_password": "..."}`. **200 OK** on success,
**400** if the token is unknown, expired, or already used, **500** if a
revocation failed.

1. `take_reset_token` hashes the presented token and removes the entry.
   Missing or older than `password_reset_token_ttl_secs` (default 1800) -> 400.
   Single-use: the entry is gone whether or not the rest succeeds.
2. **Revoke** every refresh token and login session for the user.
3. Hash `new_password` with Argon2 on `spawn_blocking` -- it's deliberately
   CPU-heavy synchronous work and would otherwise stall a tokio worker.
4. `set_password`. `UserNotFound` -> 400, reported as the same token-shaped
   error since from the caller's side the token no longer resolves to anything.
5. **Revoke again.**

### Why revoke twice

A password reset is the standard remediation for "my account may be
compromised". That only remediates anything if it also kills the credentials an
attacker already holds -- otherwise they keep a live refresh token family (TTL
30 days) straight through the reset.

The first pass kills what existed before the call. The second kills anything
created in the window between them, e.g. a login racing this request with the
old password. Neither pass may fail silently: `revoke_all_for_user` returns
`RevokeOutcome`, and `Failed` becomes a 500 rather than a 200 over a reset that
left stale sessions alive. The in-memory implementation can't fail and always
returns `Ok`; the trait doc requires durable backends not to swallow errors
there.

## Token summary

| Property       | Value                                                    |
|----------------|----------------------------------------------------------|
| Entropy        | 32 bytes CSPRNG (`rand::rng()`), base64url, no padding   |
| At rest        | `sha256(token)` as the map key; plaintext never stored   |
| TTL            | `password_reset_token_ttl_secs`, default 1800            |
| Reuse          | Single-use, consumed on `/confirm` regardless of outcome |
| Concurrent     | One live token per user; issuing drops the previous      |
| Expiry cleanup | `sweep_expired`, run by the background task in `AppState`|
| Exposure       | Never in a response, never logged                        |

Unsalted SHA-256 is correct here: the input is 256 bits of CSPRNG output, so
there is nothing to brute-force, and the lookup has to be deterministic.

## Known gaps

- **No delivery channel.** See the note at the top.
- **No rate limiting** on `/request`. Once delivery lands this is an
  email-bombing vector. The router has no rate limiting on any route today.
- **No password policy** on `new_password` -- an empty string is accepted.
  `/register` has the same gap.
- **`email_verified` stays `false`** after a reset. A completed reset does
  prove inbox control, so flipping it to `true` is defensible once delivery is
  real; leaving it false is the conservative direction in the meantime.
- **`retain` is O(n) per request**, scanning under the store's lock. The table
  is bounded at one entry per user, so this is fine at current scale; a
  durable backend gets it free (`DELETE WHERE user_id = $1`).
