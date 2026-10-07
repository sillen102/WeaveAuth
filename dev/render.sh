#!/bin/sh
# Renders ory/kratos/kratos.yml and ory/hydra/hydra.yml (local-prod's https hosts, in-network hooks) for the
# host-run stack of `mise run all`: everything on http://localhost, hooks on the host. Output is git-ignored.
set -eu
cd "$(dirname "$0")"
mkdir -p .gen
sed -e 's|https://login.localhost:8443|http://localhost:8081|g' \
    -e 's|https://bff.localhost:8443|http://localhost:8080|g' \
    -e 's|http://weaveauth:1983|http://host.docker.internal:1983|g' \
    -e 's|id: login.localhost|id: localhost|' \
    -e 's|haveibeenpwned_enabled: true|haveibeenpwned_enabled: false|' \
    -e 's|http://hydra-admin:4445|http://hydra:4445|' \
    -e 's|smtp://mail:1025/|smtp://mail:1025/?disable_starttls=true|' \
    ../ory/kratos/kratos.yml > .gen/kratos.yml
# Hydra's public API is published directly, so the issuer is its own address, not the login host.
sed -e 's|issuer: https://login.localhost:8443|issuer: http://localhost:4444|' \
    -e 's|https://login.localhost:8443|http://localhost:8081|g' \
    -e 's|https://bff.localhost:8443|http://localhost:8080|g' \
    -e 's|http://weaveauth:1983|http://host.docker.internal:1983|g' \
    -e 's|allowed_top_level_claims: \[roles, email, email_verified\]|allowed_top_level_claims: [roles, email, email_verified, first_name, last_name, phone_number]|' \
    ../ory/hydra/hydra.yml > .gen/hydra.yml
if grep -n 'login.localhost:8443\|bff.localhost:8443\|weaveauth:1983' .gen/kratos.yml .gen/hydra.yml; then
  echo "render.sh: a local-prod URL was not rewritten" >&2; exit 1
fi
grep -q 'allowed_top_level_claims: \[roles, email, email_verified, first_name' .gen/hydra.yml ||
  { echo "render.sh: allowed_top_level_claims not rewritten" >&2; exit 1; }
