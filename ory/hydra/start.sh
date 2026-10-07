#!/bin/sh
# Container entrypoint: fills the token hook's API key into hydra.yml (Hydra can't read it from env),
# then serves. Argument: all (default), public or admin; local-prod runs public and admin as two containers.
set -eu
case "${WA_HOOKS_API_KEY}" in
  "" | *[!A-Za-z0-9_.-]*) echo "WA_HOOKS_API_KEY must be non-empty and only A-Z a-z 0-9 _ . - (hex or base64url)" >&2; exit 1 ;;
esac
umask 077
sed -e "s|@WA_HOOKS_API_KEY@|${WA_HOOKS_API_KEY}|g" /etc/hydra/hydra.yml > /tmp/hydra.yml
# HYDRA_DEV=1 adds --dev (http issuer, for dev/docker-compose.yml only).
dev=""
if [ "${HYDRA_DEV:-}" = 1 ]; then
  echo "start.sh: HYDRA_DEV=1, serving with --dev (http issuer; never in production)" >&2
  dev="--dev"
fi
case "${1:-all}" in
  all) exec hydra serve all --sqa-opt-out $dev -c /tmp/hydra.yml ;;
  public | admin) exec hydra serve "$1" --sqa-opt-out $dev -c /tmp/hydra.yml ;;
  *) echo "usage: start.sh [all|public|admin]" >&2; exit 1 ;;
esac
