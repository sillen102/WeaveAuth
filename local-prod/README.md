# local-prod

The shipped image plus Ory Kratos and Hydra and Postgres, behind TLS, close to the network layout a real
deployment should have; a real one adds a NetworkPolicy so only trusted services reach the internal ports
(Docker networks cannot restrict a container to some ports). Throwaway: a local CA, a local mail sink.
Ory's configuration and what it does is in [`../ory/README.md`](../ory/README.md).

```bash
./gen-certs.sh                # once; writes certs/ (git-ignored). To regenerate: rm -rf certs first
./gen-secrets.sh              # once; writes .env (git-ignored) with random secrets
docker compose up -d --build  # from this directory
docker compose down -v        # -v also drops the Postgres data (identities); .env's secrets belong to that data, so regenerate both
```

| URL                            | What                                    |
|--------------------------------|-----------------------------------------|
| https://login.localhost:8443   | login pages, `/self-service/*` (via login), Hydra's `/oauth2/auth` and logout |
| https://bff.localhost:8443     | bff                                     |
| http://127.0.0.1:8025          | Mailpit UI (verification/recovery codes)|

Trust `certs/ca.crt` in your browser (or `curl --cacert certs/ca.crt`) to avoid the warning.

## Services and networks

```
host 127.0.0.1:8443 ── caddy ──(edge)── weaveauth (bff 8080, login 8081)
                                   └─── hydra (public 4444)
internal: weaveauth (hooks 1983, bff internal 8082), kratos (4433/4434), hydra (4444), hydra-admin (4445), postgres, mail
egress:   kratos only (Google sign-in, breached-password check)
host 127.0.0.1:8025 ──(mail-ui)── mail
```

- `postgres` holds the `kratos` and `hydra` databases; `kratos-migrate` / `hydra-migrate` are one-shots;
  `hydra-init` creates or updates Hydra's one client (bff) from `.env`'s `WA_BFF_CLIENT_SECRET`.
- Hydra runs as two containers on one database: `hydra` (public API, on `edge` and `internal`) and
  `hydra-admin` (admin API, `internal` only), so Caddy has no route to the admin API even by mistake.
  `hydra-init`, Kratos, hooks, login and key rotation all use `hydra-admin:4445`.
- `public`: only caddy. `edge` (internal): caddy, weaveauth, hydra. `internal` (internal): everything else.
  `egress` (not internal): kratos only. `mail-ui`: mail only, so its UI can be published.
- Caddy routes `/oauth2/auth` and `/oauth2/sessions/logout` to Hydra and everything else on the login host
  to login, which alone forwards `/self-service/*` and `/.well-known/ory/*` to Kratos (rate limited). Never
  route those to Kratos directly. Hydra's token, JWKS and admin endpoints are not routed.
- Kratos's courier trusts the local CA through `SSL_CERT_DIR` (next to the system roots, which Google needs).
- `config.yaml` is read by bff and hooks (login reads env vars alone); everything the stack needs is env in `docker-compose.yml`.

## `.env`

`gen-secrets.sh` writes the database passwords, the Kratos and Hydra secrets, `WA_HOOKS_API_KEY`,
`WA_BFF_INTERNAL_API_KEY` and `WA_BFF_CLIENT_SECRET`, plus:

- `KRATOS_SESSION_ON_REGISTRATION=1` (or `true`): sign in right after registration (drops verified-email-first); any other non-empty value stops Kratos from starting. Also set `WA_REQUIRE_VERIFIED_EMAIL=false`, or hooks' token hook refuses the unverified address.
- Google: `KRATOS_CONFIG_EXTRA=/etc/kratos/oidc-google.yml` (or `oidc-google-phone.yml` to also read the phone
  number), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`;
  register `https://login.localhost:8443/self-service/methods/oidc/callback/google` at Google.

## Behaviour checks

`../ory/checks/docker-compose.checks.yml` replaces the weaveauth image with a logging stub and adds a fake
IdP; see `../ory/README.md#behaviour-checks`.
