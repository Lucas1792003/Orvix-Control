#!/usr/bin/env bash
# Preflight: verify the isolated dev resources are free (or already ours) BEFORE creating anything.
# Fails closed: any conflict stops here.
set -euo pipefail
DB_PORT=55440
APP_PORT=3410
PREFIX="orvix-control-"
fail() { echo "PREFLIGHT FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable"

ours_running=$(docker ps --filter "name=^/${PREFIX}db$" --format '{{.Names}}')

# Port 55440: must be free, or held by our own container.
if lsof -nP -iTCP:${DB_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
  if [[ -z "$ours_running" ]]; then
    fail "port ${DB_PORT} is in use by something other than ${PREFIX}db"
  fi
  holder=$(docker port "${PREFIX}db" 5432/tcp 2>/dev/null || true)
  [[ "$holder" == "127.0.0.1:${DB_PORT}" ]] || fail "port ${DB_PORT} in use, but ${PREFIX}db is not publishing it (got: '${holder}')"
  echo "port ${DB_PORT}: held by ${PREFIX}db (ours)"
else
  echo "port ${DB_PORT}: free"
fi

# Port 3410: must be free unless --allow-app-running (used by e2e against our own server).
if lsof -nP -iTCP:${APP_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
  if [[ "${1:-}" == "--allow-app-running" ]]; then
    echo "port ${APP_PORT}: in use (allowed by flag)"
  else
    fail "port ${APP_PORT} is in use; stop it or choose to reuse it explicitly"
  fi
else
  echo "port ${APP_PORT}: free"
fi

# Any Docker object with our prefix must be one we expect.
for kind in container volume network; do
  case $kind in
    container) names=$(docker ps -a --format '{{.Names}}' | grep "^${PREFIX}" || true); expected="${PREFIX}db";;
    volume)    names=$(docker volume ls --format '{{.Name}}' | grep "^${PREFIX}" || true); expected="${PREFIX}pgdata";;
    network)   names=$(docker network ls --format '{{.Name}}' | grep "^${PREFIX}" || true); expected="${PREFIX}net";;
  esac
  for n in $names; do
    [[ "$n" == "$expected" ]] || fail "unexpected ${kind} '${n}' with prefix ${PREFIX}"
  done
  echo "${kind}: ${names:-<none>}"
done

# Nothing in this project may point at a non-loopback database.
if [[ -f .env.local ]]; then
  host_line=$(grep -c '^ORVIX_DB_HOST=127.0.0.1$' .env.local || true)
  [[ "$host_line" == "1" ]] || fail ".env.local ORVIX_DB_HOST must be exactly 127.0.0.1"
fi
echo "PREFLIGHT OK"
