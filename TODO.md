# TODO

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
      The two mitigations hold today.
- [ ] **Raise the prod auth rate limit.** `WA_RATE_LIMIT_MAX_ATTEMPTS` defaults to 10 a minute
      per client in bff and for login's submissions, and users behind CGNAT or a corporate NAT all
      share one client address, so a busy office can lock itself out of sign-in. login's
      per-identifier throttle stops password guessing, so the per-address limit only has to stop
      floods: raise the prod default (e.g. 30 to 60) and update the README row.
- [ ] **A /48 rate-limit bucket for IPv6.** Clients are keyed on their /64, so a holder of a
      routed /48 gets 65536 separate budgets (the `ponytail:` note on `per_network` in
      `common/src/rate_limit.rs`). Check a second key per request: the /48, with a larger
      shared budget (e.g. 10x), next to the /64 one. Not the /48 alone, as ISPs hand each customer
      a /56 out of a shared /48. Lower priority, as login's per-identifier throttle caps guesses per account.
- [ ] **A CAPTCHA or proof-of-work instead of a flat `429` (optional).** After N failures from
      one client address, ask for a challenge rather than rejecting, so real users behind a
      shared address get a hurdle instead of a lockout. Only if the raised limit still turns out
      too tight in practice.
- [ ] **Verification started by a login ends on Kratos' `/error`.** An unverified user who logs
      in gets a verification flow; entering the code verifies the address but the flow ends on
      `/error` (the login session was never persisted) instead of continuing to Hydra, so the
      user has to sign in again. Make `login`'s `/error` say so, or find a Kratos setting that
      keeps the OAuth2 challenge through that path (`ory/README.md`, check 6).
- [ ] **Profile APIs cannot see the scopes the user granted.** Kratos' after-registration hook
      context carries neither provider tokens nor granted scopes, so `profile_apis[].scope` cannot
      be checked and the call is always made. A declined permission only shows as a failed call,
      which fails the registration just for a `required` entry.
- [ ] **The per-identifier login throttle is per `login` instance.** Counts live in memory, so
      several `login` replicas each allow their own free attempts, and a restart resets them. Back
      it with a shared store if `login` is ever scaled out.
