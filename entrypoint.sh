#!/bin/sh
set -eu

TOKEN_DIR="${SOFTHSM2_TOKEN_DIR:-/home/hsm/tokens}"
TOKEN_LABEL="${SOFTHSM2_TOKEN_LABEL:-mytoken}"
USER_PIN="${SOFTHSM2_PIN:-1234}"
SO_PIN="${SOFTHSM2_SO_PIN:-12345678}"

mkdir -p "$TOKEN_DIR"

# Initialize the default token only when the store is empty (first run with a
# fresh volume). Existing tokens are preserved across container restarts.
if [ -z "$(find "$TOKEN_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]; then
    echo "Initializing SoftHSM token '$TOKEN_LABEL'..."
    softhsm2-util --init-token --free \
        --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" \
        --pin "$USER_PIN"
fi

exec "$@"
