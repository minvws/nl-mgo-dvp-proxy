# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

ARG PYTHON_VERSION=3.11

FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-bookworm-slim AS base

ARG PROJECT_DIR="/src" \
    APP_USER="app" \
    APP_GROUP="app" \
    NEW_UID=1000 \
    NEW_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

# Create a non-privileged user that the app will run under.
RUN groupadd --system ${APP_GROUP} --gid=${NEW_GID} && \
    adduser \
    --disabled-password \
    --gecos "" \
    --uid ${NEW_UID} \
    --gid ${NEW_GID} \
    ${APP_USER}

RUN apt-get update && \
    apt-get install -y \
    git \
    gnupg2 \
    make \
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Add the SSH public keys of the Git server to the known hosts (here, github.com)
RUN mkdir -p /etc/ssh && ssh-keyscan github.com >> /etc/ssh/ssh_known_hosts

WORKDIR ${PROJECT_DIR}

FROM base AS builder

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=ssh \
    uv sync --locked --dev

FROM base AS final

ARG PROJECT_DIR
ARG APP_USER
ARG APP_GROUP

COPY --chown=${APP_USER}:${APP_GROUP} --from=builder ${PROJECT_DIR}/.venv ${PROJECT_DIR}/.venv
COPY --chown=${APP_USER}:${APP_GROUP} docker/entrypoint.sh /var/run/entrypoint.sh

RUN chmod +x /var/run/entrypoint.sh
RUN mkdir -p secrets && chown ${APP_USER}:${APP_GROUP} secrets

USER ${APP_USER}
WORKDIR ${PROJECT_DIR}

ENV PYTHONPATH=${PROJECT_DIR} \
    PATH=${PROJECT_DIR}/.venv/bin:$PATH

ENTRYPOINT ["/var/run/entrypoint.sh"]
