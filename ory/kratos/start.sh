#!/bin/sh
# Container entrypoint: fills the @PLACEHOLDER@ secrets into the mounted config files (Kratos can't
# read secrets for hook auth from env), then serves. Config files are layered with -c, later wins.
#   KRATOS_SESSION_ON_REGISTRATION  1 or true: also load session-on-registration.yml; unset or empty: don't
#   KRATOS_CONFIG_EXTRA             extra config files (absolute paths, space separated): OIDC providers, ...
set -eu
umask 077

# The values go through sed into YAML: refuse anything that could break out of a scalar.
safe() {
  case "$2" in
    *[!A-Za-z0-9_.-]*) echo "$1 may only contain A-Z a-z 0-9 _ . - (hex or base64url for secrets)" >&2; exit 1 ;;
  esac
}
safe WA_HOOKS_API_KEY "${WA_HOOKS_API_KEY}"
[ -n "${WA_HOOKS_API_KEY}" ] || { echo "WA_HOOKS_API_KEY is required" >&2; exit 1; }
safe GOOGLE_CLIENT_ID "${GOOGLE_CLIENT_ID:-}"
safe GOOGLE_CLIENT_SECRET "${GOOGLE_CLIENT_SECRET:-}"

n=0
args=""
render() {
  n=$((n + 1))
  out="/tmp/$n-$(basename "$1")"
  sed -e "s|@WA_HOOKS_API_KEY@|${WA_HOOKS_API_KEY}|g" \
      -e "s|@GOOGLE_CLIENT_ID@|${GOOGLE_CLIENT_ID:-}|g" \
      -e "s|@GOOGLE_CLIENT_SECRET@|${GOOGLE_CLIENT_SECRET:-}|g" \
      "$1" > "$out"
  args="$args -c $out"
}

render /etc/kratos/kratos.yml
case "${KRATOS_SESSION_ON_REGISTRATION:-}" in
  "") ;;
  1 | true) render /etc/kratos/session-on-registration.yml ;;
  *) echo "KRATOS_SESSION_ON_REGISTRATION must be 1 or true, or unset" >&2; exit 1 ;;
esac
google_files=0
for f in ${KRATOS_CONFIG_EXTRA:-}; do
  case "$(basename "$f")" in oidc-google.yml | oidc-google-phone.yml) google=1 ;; *) google= ;; esac
  if [ -n "$google" ]; then
    google_files=$((google_files + 1))
    # The later file would replace the other's providers list, whichever order they come in.
    [ "$google_files" -le 1 ] || { echo "load only one of oidc-google.yml, oidc-google-phone.yml" >&2; exit 1; }
  fi
  if [ -n "$google" ] && { [ -z "${GOOGLE_CLIENT_ID:-}" ] || [ -z "${GOOGLE_CLIENT_SECRET:-}" ]; }; then
    echo "$(basename "$f") is loaded: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET" >&2; exit 1
  fi
  render "$f"
done
# shellcheck disable=SC2086
exec kratos serve --sqa-opt-out $args --watch-courier
