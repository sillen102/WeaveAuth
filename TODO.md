# TODO

- [ ] **Password reset can't be completed yet.** An OIDC login whose email matches an existing
      but unverified local account can't merge into it automatically (would be an
      account-takeover vector -- see `UserStorage::resolve_oidc_login`), so it's routed to
      `/oauth/oidc/confirm-link`, which requires that account's *current* password. If the
      account was squatted by someone else (the real owner never had a password for it, e.g.
      an attacker pre-registered their email), the real owner is stuck. The
      `/oauth/password-reset/request` and `/confirm` endpoints exist, but there is no outbound
      email (no SMTP/transactional-email integration anywhere in the codebase), so the reset
      token can never reach the user -- see `docs/flows/password-reset.md`. Once delivery
      exists, a completed reset should also flip that account's `email_verified` to `true`
      (mailbox control is proof of ownership, same as an OIDC provider's; `/confirm` doesn't
      do this today), which lets a subsequent OIDC login link automatically via the existing
      verified-match path.
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
