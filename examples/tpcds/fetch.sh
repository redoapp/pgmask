#!/usr/bin/env bash
# Fetch the TPC-DS schema and 99 queries into a gitignored directory.
#
# The queries and DDL are TPC's, under their own licence, so they are downloaded
# rather than vendored into this repo.

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p corpus/queries

echo "==> schema"
curl -sSL -o corpus/tpcds.sql \
  https://raw.githubusercontent.com/gregrahn/tpcds-kit/master/tools/tpcds.sql

echo "==> 99 queries"
for i in $(seq 1 99); do
  curl -sSL -o "corpus/queries/query_${i}.sql" \
    "https://raw.githubusercontent.com/Altinity/tpc-ds/master/queries/query_${i}.sql"
done
echo "done: $(ls corpus/queries | wc -l | tr -d ' ') queries"
