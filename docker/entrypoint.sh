#!/bin/sh
set -eu

umask 077

quality_guard_dir=/var/lib/grok2api-quality-guard
mkdir -p "${quality_guard_dir}"
chown grok2api:grok2api "${quality_guard_dir}"
chmod 0700 "${quality_guard_dir}"

mkdir -p /app/data
chown grok2api:grok2api /app/data

if [ -f "${GROK2API_CONFIG_SOURCE}" ]; then
  cp "${GROK2API_CONFIG_SOURCE}" /app/config.yaml
elif [ -n "${GROK2API_CONFIG_B64:-}" ]; then
  if ! printf '%s' "${GROK2API_CONFIG_B64}" | base64 -d > /app/config.yaml; then
    echo "GROK2API_CONFIG_B64 is not valid base64" >&2
    exit 1
  fi
else
  missing=""
  [ -n "${GROK2API_JWT_SECRET:-}" ] || missing="${missing} GROK2API_JWT_SECRET"
  [ -n "${GROK2API_CREDENTIAL_ENCRYPTION_KEY:-}" ] || missing="${missing} GROK2API_CREDENTIAL_ENCRYPTION_KEY"
  [ -n "${GROK2API_ADMIN_USERNAME:-}" ] || missing="${missing} GROK2API_ADMIN_USERNAME"
  [ -n "${GROK2API_ADMIN_PASSWORD:-}" ] || missing="${missing} GROK2API_ADMIN_PASSWORD"
  if [ -n "${missing}" ]; then
    echo "missing config: ${GROK2API_CONFIG_SOURCE}" >&2
    echo "mount config.yaml, set GROK2API_CONFIG_B64, or configure:${missing}" >&2
    exit 1
  fi
  # An empty file selects application defaults; sensitive values are applied
  # from environment variables by the configuration loader.
  : > /app/config.yaml
fi

if [ -n "${RAILWAY_PUBLIC_DOMAIN:-}" ] && [ -z "${GROK2API_PUBLIC_API_BASE_URL:-}" ]; then
  export GROK2API_PUBLIC_API_BASE_URL="https://${RAILWAY_PUBLIC_DOMAIN}"
fi
if [ -n "${RAILWAY_ENVIRONMENT_ID:-}" ] && [ -z "${GROK2API_SECURE_COOKIES:-}" ]; then
  export GROK2API_SECURE_COOKIES=true
fi

chown grok2api:grok2api /app/config.yaml
chmod 0600 /app/config.yaml

exec su-exec grok2api:grok2api "$@"
