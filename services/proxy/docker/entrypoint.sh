#!/usr/bin/env bash

APP_PORT="${APP_PORT:-8001}"
USE_TLS="${USE_TLS:-0}"
SSL_KEY_PATH="${SSL_KEY_PATH:-}"
SSL_CERT_PATH="${SSL_CERT_PATH:-}"
CLIENT_ASSERTION_JWT_KEY_PATH="${CLIENT_ASSERTION_JWT_KEY_PATH:-}"
JWE_KEY_PATH="${JWE_KEY_PATH:-}"
JWT_SIGNING_KEY_PATH="${JWT_SIGNING_KEY_PATH:-}"

python3 tools/generate_oauth_state_signing_key.py secrets/oauth_state_signing_key.key --force

python3 tools/generate-oidc-state-secret.py

python3 tools/generate-key-pair.py \
    --name=client_assertion_jwt \
    --path=$CLIENT_ASSERTION_JWT_KEY_PATH

python3 tools/generate-key-pair.py \
    --name=jwe \
    --path=$JWE_KEY_PATH

python3 tools/generate-key-pair.py \
    --type=ec \
    --name=placeholder_jwt_signing \
    --path=$JWT_SIGNING_KEY_PATH

[ "$USE_TLS" = 1 ] && \
    uvicorn app.main:create_app --reload --factory --host 0.0.0.0 --port $APP_PORT --ssl-keyfile $SSL_KEY_PATH --ssl-certfile $SSL_CERT_PATH || \
    uvicorn app.main:create_app --reload --factory --host 0.0.0.0 --port $APP_PORT
