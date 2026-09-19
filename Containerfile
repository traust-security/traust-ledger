# ── Builder stage ───────────────────────────────────────────────────
# Hardened, RPM-based Python builder image from a public registry
# (registry.access.redhat.com needs no credentials). Pinned by digest.
#
# MUST stay on the same Python minor as the runtime stage below: the .venv
# built here is copied wholesale into the runtime, and native-extension .so
# files are ABI-pinned per minor while the venv's script shebangs hardcode
# the builder's interpreter path.
FROM registry.access.redhat.com/hi/python:3.12-builder@sha256:da4102d0cb873054a799e6614de8320b8874865bfc17d1bb3cc76e60cbed6f91 AS builder

ARG UV_VERSION=0.7

USER 0

# git is required for uv to resolve the git-tag dependency pins
# (traust-contracts). Installed via microdnf (the base image is RPM-based).
RUN microdnf install -y git ca-certificates \
    && microdnf clean all

RUN pip install --no-cache-dir "uv>=${UV_VERSION}"

WORKDIR /build

# Dependency layer first — cache-friendly when only source changes.
COPY pyproject.toml uv.lock ./

# Dependency pins are public git tags and resolve without credentials.
# A deployment that builds from a private mirror of those repositories may
# pass PRIVATE_GIT_SSH_BASE (the ssh:// prefix recorded in uv.lock) and
# PRIVATE_GIT_HTTPS_HOST (the host to fetch it from over HTTPS) plus a read
# token as the mounted secret `traust-ledger-git-auth/token`; git's insteadOf
# rewrite then maps the pins to authenticated HTTPS for this RUN only, in a
# throwaway config the builder stage discards. PRIVATE_GIT_INSECURE_TLS=1
# additionally skips TLS verification for that one host (a mirror signed by
# a CA the base image does not trust; the token remains the access control).
# Nothing here names any host; all three default to off.
ARG PRIVATE_GIT_SSH_BASE=""
ARG PRIVATE_GIT_HTTPS_HOST=""
ARG PRIVATE_GIT_INSECURE_TLS=""
RUN --mount=type=secret,id=traust-ledger-git-auth/token,required=false <<'EOF'
set -eu
if [ -n "${PRIVATE_GIT_SSH_BASE}" ] && [ -n "${PRIVATE_GIT_HTTPS_HOST}" ] \
   && [ -f /run/secrets/traust-ledger-git-auth/token ]; then
  TOKEN="$(cat /run/secrets/traust-ledger-git-auth/token)"
  git config --global \
      "url.https://oauth2:${TOKEN}@${PRIVATE_GIT_HTTPS_HOST}/.insteadOf" \
      "${PRIVATE_GIT_SSH_BASE}"
  if [ "${PRIVATE_GIT_INSECURE_TLS}" = "1" ]; then
    git config --global "http.https://${PRIVATE_GIT_HTTPS_HOST}/.sslVerify" false
  fi
fi
uv sync --frozen --extra service --no-install-project
if [ -n "${PRIVATE_GIT_HTTPS_HOST}" ]; then
  git config --global --remove-section "url.https://oauth2:${TOKEN:-}@${PRIVATE_GIT_HTTPS_HOST}/" 2>/dev/null || true
  git config --global --unset "http.https://${PRIVATE_GIT_HTTPS_HOST}/.sslVerify" 2>/dev/null || true
fi
EOF

COPY . .
RUN uv build --wheel --out-dir /build/dist

# Install the built wheel into the venv so the runtime stage gets a
# single self-contained tree.
RUN uv pip install --no-deps /build/dist/*.whl

# PostgreSQL driver for the db backend (LAAS_BACKEND_TYPE=db). Deliberately
# installed only in the image, never in pyproject.toml/uv.lock, so local
# clones, uv sync, and the test suite stay driver-free (SQLite needs none).
# psycopg is LGPL-3.0-only and ships unmodified from PyPI as a separately
# replaceable library; any postgresql+psycopg:// URL requires it.
ARG PSYCOPG_VERSION=3.1
RUN uv pip install "psycopg[binary]>=${PSYCOPG_VERSION}"

# ── cosign source ───────────────────────────────────────────────────
# Take the cosign binary from a digest-pinned hardened image rather than
# downloading a release at build time: no network fetch in the build.
FROM registry.access.redhat.com/hi/cosign:latest@sha256:df8a3f9bbea6e7bcfcf0813c87898a8ad401e69ae40229c7be22ab75d9a33c11 AS cosign

# ── Runtime stage ───────────────────────────────────────────────────
# Minimal hardened Python runtime. Runs as a non-root user (UID 1001) by
# default and ships no package manager, so nothing is installed here.
# Python minor must match the builder stage above (see note there).
FROM registry.access.redhat.com/hi/python:3.12@sha256:65b88fd52b1133a118c9085a90cc3c6d940c83d2c5073523ccde34f23366c0e2 AS runtime

# OCI labels. VERSION and SOURCE_REVISION are supplied by the build.
ARG SOURCE_REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/traust-security/traust-ledger" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="traust-ledger" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      name="traust/traust-ledger" \
      version="${VERSION}" \
      vendor="Traust maintainers" \
      url="https://github.com/traust-security/traust-ledger" \
      summary="Traust disposition-ledger service" \
      description="Disposition-ledger kernel: finding identity, event math, integrity (Merkle + signing), and the single ledger write path." \
      io.k8s.description="Traust disposition-ledger service." \
      io.k8s.display-name="Traust Ledger Service" \
      maintainer="Traust maintainers <traust@redhat.com>"

# cosign lives in the image so event-signing can call it without an
# external sidecar; the key itself never ships here.
COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign

COPY --from=builder /build/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG APP_PORT=8000
EXPOSE ${APP_PORT}

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:${APP_PORT}/healthz').raise_for_status()"

# The base image already defaults to a non-root user (UID 1001).
USER 1001

ENTRYPOINT ["uvicorn", "traust_ledger.service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
