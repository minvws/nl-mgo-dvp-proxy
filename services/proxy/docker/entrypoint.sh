#!/usr/bin/env bash

APP_PORT="${APP_PORT:-8001}"
USE_TLS="${USE_TLS:-0}"
SSL_KEY_PATH="${SSL_KEY_PATH:-}"
SSL_CERT_PATH="${SSL_CERT_PATH:-}"
CLIENT_ASSERTION_JWT_PVT_KEY_PATH="${CLIENT_ASSERTION_JWT_PVT_KEY_PATH:-}"
CLIENT_ASSERTION_JWT_PUB_KEY_PATH="${CLIENT_ASSERTION_JWT_PUB_KEY_PATH:-}"

python3 tools/generate_oauth_state_signing_key.py secrets/oauth_state_signing_key.key --force
python3 tools/generate-oidc-state-secret.py
python3 tools/generate-client-assertion-jwt-key-pair.py \
    --pvt-key-path=$CLIENT_ASSERTION_JWT_PVT_KEY_PATH \
    --pub-key-path=$CLIENT_ASSERTION_JWT_PUB_KEY_PATH

[ "$USE_TLS" = 1 ] && \
    uvicorn app.main:create_app --reload --factory --host 0.0.0.0 --port $APP_PORT --ssl-keyfile $SSL_KEY_PATH --ssl-certfile $SSL_CERT_PATH || \
    uvicorn app.main:create_app --reload --factory --host 0.0.0.0 --port $APP_PORT
