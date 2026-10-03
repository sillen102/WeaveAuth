# TODO

- [ ] **Password reset can't be completed yet.** An OIDC login whose email matches an existing
      account the identity isn't linked to never links automatically (would be an
      account-takeover vector -- see `UserStorage::resolve_oidc_login`); the user confirms with
      the account's *current* password or a sign-in through a provider already linked to it.
      If the account was squatted by someone else (the real owner never had a password for
      it, e.g. an attacker pre-registered their email), or has no password and its owner lost
      access to every linked provider, the real owner is stuck. The
      `/oauth/password-reset/request` and `/confirm` endpoints exist, but there is no outbound
      email (no SMTP/transactional-email integration anywhere in the codebase), so the reset
      token can never reach the user -- see `docs/flows/password-reset.md`. Once delivery
      exists, a reset gives the owner a password to confirm the link with, and should also
      flip the account's `email_verified` to `true` (mailbox control; `/confirm` doesn't do
      this today).
- [ ] **No server-side password policy.** `minlength="8"` on `register.html` is client-side
      only; `register.rs` accepts any length, including empty, via a direct API call.
- [ ] **Client authentication.** The bff's token-exchange request already carries
      `client_id`/`client_secret` fields (currently always `None`); wiring real client
      credentials into the backend's `/oauth/token` is future work for defense in depth
      alongside PKCE.
- [ ] **No CSRF token on the authenticated proxy layer.** Once a user has the `wa_session`
      cookie, any state-changing request `proxy.rs` forwards is the classic CSRF shape
      (ambient cookie auth, attached automatically regardless of which site triggered the
      request). Currently mitigated only by `SameSite=Lax` on the cookie (blocks it on
      cross-site POST, but still sent on a top-level cross-site GET, and offers nothing if the
      cookie ever needs `SameSite=None`, e.g. for a cross-site embedded frontend). A
      double-submit cookie (random value set on login, required to match a header/field on
      state-changing proxied requests) would add real defense-in-depth here, independent of
      browser SameSite support. Lower priority than the items above -- `SameSite=Lax` is a
      working mitigation today.
