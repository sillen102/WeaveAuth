# TODO

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
