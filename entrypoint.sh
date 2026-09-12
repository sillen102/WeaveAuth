#!/bin/sh
set -e
weaveauth &
weaveauth-bff &
weaveauth-login &
wait