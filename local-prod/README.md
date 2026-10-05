# local-prod

The shipped image under the `prod` profile, behind TLS, close to the network layout a real
deployment should have; a real one adds a NetworkPolicy so only trusted services reach backend's
1983 (here caddy and mail can). Throwaway: in-memory storage, a local CA, a local mail sink.

```bash
./gen-certs.sh                # once; writes certs/ (git-ignored). To regenerate: rm -rf certs first
docker compose up -d --build  # from this directory
docker compose down           # all state is in memory, so this resets it
```

| URL                            | What                                    |
|--------------------------------|-----------------------------------------|
| https://login.localhost:8443   | login pages                             |
| https://bff.localhost:8443     | bff                                     |
| http://127.0.0.1:8025          | Mailpit UI (verification/reset emails)  |

Trust `certs/ca.crt` in your browser (or `curl --cacert certs/ca.crt`) to avoid the warning.

## Networks

The image runs as one container, exactly as shipped (`weaveauth-launcher` starts all three
services).

```
host 127.0.0.1:8443 ── caddy ──(edge)── weaveauth (bff 8080, login 8081, backend 1983)
                                            └──(internal)── mail (SMTP, STARTTLS required)
host 127.0.0.1:8025 ──(mail-ui)── mail (web UI)
```

- `public`: only caddy. A container you attach here sees what the internet would.
- `edge` (internal): caddy and weaveauth. Caddy's address is pinned (`172.30.0.2`) because bff
  trusts its `X-Forwarded-For` (`WA_TRUSTED_PROXIES`).
- `internal` (internal): weaveauth and mail. bff and login answer on both of weaveauth's
  networks, and so does backend (1983): both caddy and mail can reach backend's API. Docker networks
  can't restrict a container to some ports or one direction, and backend has to reach mail. A
  service you add to `internal` verifies access tokens by discovering from the issuer,
  `http://weaveauth:1983` (`WA_BACKEND_URL`).
- `mail-ui`: only mail, so its UI can be published to the host.

`internal: true` networks have no route out, so weaveauth can't reach the internet. `config.yaml`
is read by both backend and bff: a key only one knows is ignored by the other, but one both know
(`profile`, `port`, `bff_url`, `login_public_url`) applies to both.

A container on `public` has to send `*.localhost` to caddy itself, because curl and browsers
always resolve `*.localhost` to loopback:

```bash
docker run --rm --network weaveauth-local-prod_public -v "$PWD/certs:/c:ro" curlimages/curl \
  --cacert /c/ca.crt --connect-to bff.localhost:8443:caddy:8443 https://bff.localhost:8443/health
```

## Not included

- No bff `routes`, plugins or OIDC providers. Add routes and plugins to `config.yaml` the way the
  root README describes; plugins also need `cap_drop`/`no-new-privileges` relaxed (see
  `docs/plugins.md#deploying`). OIDC providers need more: every network weaveauth is on is
  `internal: true` (no egress), and `SSL_CERT_FILE` trusts only the local CA, so backend reaches
  neither a provider's discovery nor its token endpoint. Give weaveauth a network with egress,
  and drop `SSL_CERT_FILE` or point it at a bundle holding both the system CAs and the local one.
- Mail runs its own Mailpit, not `testing/mailpit`: backend refuses `tls: none` for a
  non-loopback host, so this one has STARTTLS with the local CA, and it sits on `internal`.
