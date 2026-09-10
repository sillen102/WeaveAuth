#!/bin/sh
set -e
weaveauth &
weaveauth-login &
weaveauth-frontend &
wait