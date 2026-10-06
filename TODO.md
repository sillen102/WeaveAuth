# TODO

- [ ] **Client authentication.** The bff's token-exchange request already carries
      `client_id`/`client_secret` fields (currently always `None`); wiring real client
      credentials into the backend's `/oauth/token` is future work for defense in depth
      alongside PKCE.
- [ ] **No CSRF token on the authenticated proxy layer.** Once a user has the `wa_session`
      cookie, any state-changing request `proxy.rs` forwards is the classic CSRF shape
      (ambient cookie auth, attached automatically regardless of which site triggered the
      request). Mitigated twice today: `SameSite=Lax` on the cookie (blocks it on cross-site
      POST, but still sent on a top-level cross-site GET, and offers nothing if the cookie ever
      needs `SameSite=None`, e.g. for a cross-site embedded frontend), and the proxy's `Origin`
      check, which `403`s any method but `GET`/`HEAD`/`OPTIONS` unless `Origin` (or, failing
      that, `Referer`) names a `WA_TRUSTED_ORIGINS` origin or bff's own. What neither covers:
      an upstream that changes state on `GET`, and a request from a trusted origin that an
      attacker controls (an XSS there, or a same-site page bff trusts). A double-submit cookie
      (random value set on login, required to match a header on state-changing proxied
      requests) would add defense-in-depth independent of browser `SameSite` and `Origin`
      behaviour; bff would check that header itself, so it stays out of `REQUEST_HEADERS`.
      Lower priority than the items above -- the two
      mitigations hold today.
- [ ] **Per-account login throttle in backend.** bff's rate limit is per client address, so a
      botnet spread over many addresses can still guess one account's password, and anything on
      the internal network that calls backend's `/oauth/login` directly isn't limited at all.
      Throttle failed logins per account in backend, keyed on a hash of the normalized email,
      the way verify-email's per-user limits (`UserCodes`) work. Rules: a growing delay, not a
      lockout (e.g. 5 free failures, then 1 attempt per 30s, then per 5min; reset on success),
      so nobody can lock a victim out by failing on purpose; the same treatment and response for
      unknown emails as for known ones (alongside the dummy hash), so the throttle doesn't reveal
      which accounts exist; and memory bounded by the expiry sweep. Do this first: the next item
      depends on it.
- [ ] **Raise the prod auth rate limit.** `WA_RATE_LIMIT_MAX_ATTEMPTS` defaults to 10 a minute
      per client, and users behind CGNAT or a corporate NAT all share one client address, so a
      busy office can lock itself out of `/login`. Once the per-account throttle stops password
      guessing, the per-address limit only has to stop floods: raise the prod default (e.g. 30 to
      60) and update the README row.
- [ ] **A /48 rate-limit bucket for IPv6.** Clients are keyed on their /64, so a holder of a
      routed /48 gets 65536 separate budgets (the `ponytail:` note on `per_network` in
      `bff/src/server/rate_limit.rs`). Check a second key per request: the /48, with a larger
      shared budget (e.g. 10x), next to the /64 one. Not the /48 alone, as ISPs hand each customer
      a /56 out of a shared /48. Lower priority once the per-account throttle caps guesses per
      account anyway.
- [ ] **A CAPTCHA or proof-of-work instead of a flat `429` (optional).** After N failures from
      one client address, ask for a challenge rather than rejecting, so real users behind a
      shared address get a hurdle instead of a lockout. Only if the raised limit still turns out
      too tight in practice.
