#!/usr/bin/env bash
# Start the isolated dev database. Generates dev-only random passwords into .env.local (0600) once.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/preflight.sh "${1:-}"
if [[ ! -f .env.local ]]; then
  umask 077
  {
    echo "ORVIX_DB_HOST=127.0.0.1"
    echo "ORVIX_DB_PORT=55440"
    echo "ORVIX_DB_NAME=orvix_control"
    echo "ORVIX_DB_SUPERUSER=orvix_control_super"
    echo "ORVIX_DB_SUPERUSER_PASSWORD=$(openssl rand -hex 24)"
    echo "ORVIX_DB_APP_USER=control_app"
    echo "ORVIX_DB_APP_PASSWORD=$(openssl rand -hex 24)"
    echo "ORVIX_RP_ID=localhost"
    echo "ORVIX_ORIGIN=http://localhost:3410"
  } > .env.local
  chmod 600 .env.local
  echo "generated .env.local (dev-only secrets, not printed)"
fi
set -a; source .env.local; set +a
docker compose -f docker-compose.dev.yml up -d --wait
echo "orvix-control-db is healthy on 127.0.0.1:55440"
