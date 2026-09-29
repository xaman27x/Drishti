#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
seed=false
build=true
for arg in "$@"; do
  case "$arg" in
    --approve-builtins) export DRISHTI_APPROVE_BUILTINS=true ;;
    --seed) seed=true ;;
    --no-build) build=false ;;
    *) echo "Usage: bash scripts/run-local.sh [--approve-builtins] [--seed] [--no-build]"; exit 2 ;;
  esac
done
command -v docker >/dev/null || { echo 'Install Docker with Compose first.' >&2; exit 1; }
docker info >/dev/null
docker compose version
if [[ ! -f .env ]]; then cp .env.example .env; fi
# Validate without printing secrets.
docker compose config --quiet
trap 'echo "Startup failed. Inspect: docker compose logs --tail=100 minio bootstrap worker api" >&2' ERR
if "$build"; then docker compose build minio api frontend; fi
docker compose up -d --wait --wait-timeout 180 minio redpanda
docker compose run --rm --no-deps state-init
docker compose run --rm --no-deps topic-init
docker compose run --rm --no-deps bootstrap
# Keep the one-shot service dependency graph valid for ordinary compose up too.
docker compose up -d --wait --wait-timeout 240 worker api frontend
if "$seed"; then docker compose exec -T api python -m drishti.runtime.smoke; fi
docker compose ps
echo 'Drishti is ready. Default GUI: http://localhost:5173 ; API: http://localhost:8080/docs'
echo 'Re-run with --no-build for a warm start. Named volumes preserve evidence and state.'
