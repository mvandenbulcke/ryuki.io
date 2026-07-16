#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${RYUKI_DATABASE_URL:-}" ]]; then
  echo "error: RYUKI_DATABASE_URL must name a disposable, fully migrated PostgreSQL database" >&2
  exit 2
fi

if [[ "${RYUKI_QUERY_PLAN_REGRESSION_ACK:-}" != "disposable" ]]; then
  echo "error: set RYUKI_QUERY_PLAN_REGRESSION_ACK=disposable to acknowledge the 400,000-row temporary plan probe" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

psql \
  --no-psqlrc \
  --set=ON_ERROR_STOP=1 \
  --dbname="${RYUKI_DATABASE_URL}" \
  --file="${script_dir}/metering-usage-query-plan.sql"
