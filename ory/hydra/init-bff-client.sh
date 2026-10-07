#!/bin/sh
# Creates or updates Hydra's one OAuth2 client, bff. Idempotent: rerun after changing a flag.
# Needs HYDRA_ADMIN_URL, BFF_CLIENT_SECRET, BFF_URL, BFF_INTERNAL_URL, POST_LOGOUT_URI; BFF_CLIENT_ID and
# BFF_AUDIENCE optional. The client goes in as a JSON file (mode 600) so the secret is not on the command line.
set -eu
case "${BFF_CLIENT_SECRET}" in
  "" | *[!A-Za-z0-9_.-]*) echo "BFF_CLIENT_SECRET must be non-empty and only A-Z a-z 0-9 _ . - (hex or base64url)" >&2; exit 1 ;;
esac
id="${BFF_CLIENT_ID:-bff}"
for var in "$id" "${BFF_URL}" "${BFF_INTERNAL_URL}" "${POST_LOGOUT_URI}" "${BFF_AUDIENCE:-weaveauth}"; do
  case "$var" in
    "" | *[!A-Za-z0-9_.:/?=\&%~@+-]*) echo "bff client settings must be non-empty and free of quotes, backslashes, spaces and control characters" >&2; exit 1 ;;
  esac
done
umask 077
file=/tmp/bff-client.json
trap 'rm -f "$file"' EXIT
cat > "$file" <<JSON
{
  "client_id": "$id",
  "client_name": "bff",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid offline_access",
  "redirect_uris": ["${BFF_URL}/callback"],
  "post_logout_redirect_uris": ["${POST_LOGOUT_URI}"],
  "audience": ["${BFF_AUDIENCE:-weaveauth}"],
  "access_token_strategy": "jwt",
  "token_endpoint_auth_method": "client_secret_basic",
  "client_secret": "${BFF_CLIENT_SECRET}",
  "skip_consent": true,
  "backchannel_logout_uri": "${BFF_INTERNAL_URL}/backchannel-logout",
  "backchannel_logout_session_required": true
}
JSON
export ORY_SDK_URL="$HYDRA_ADMIN_URL"
if hydra get oauth2-client "$id" >/dev/null 2>&1; then
  hydra update oauth2-client "$id" --file "$file" >/dev/null
else
  hydra create oauth2-client --id "$id" --file "$file" >/dev/null
fi
