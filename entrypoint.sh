#!/bin/sh
set -e

# All three binaries run in this one container and need to agree on where
# the login page (not bff, not backend) is publicly reachable. login reads
# WA_LOGIN_PUBLIC_URL itself, and both bff (WA_TRUSTED_ORIGINS, login-CSRF
# check) and backend (WA_REDIRECT_URI_ALLOWLIST, post-login redirect check)
# default from it too (see bff::Config::load / backend::Config::load) --
# each still wins if the deployer sets it explicitly. Just needs exporting.
: "${WA_LOGIN_PUBLIC_URL:=http://localhost:8081}"
export WA_LOGIN_PUBLIC_URL

weaveauth &
weaveauth-bff &
weaveauth-login &
wait