#!/usr/bin/env bash
# Delete DNS records left behind by live test runs that crashed before
# their own cleanup: per-run names (r<digits>...) in the partner zone and
# challenge TXT records in the delegate zone. Baseline records (apex CAA,
# NS, SOA) are never touched. Runs in the same concurrency group as the
# live test, so it never races a run in progress.
set -euo pipefail
for v in E2E_DO_PARTNER_TOKEN E2E_DO_PARTNER_ZONE E2E_DO_PROVIDER_TOKEN E2E_DO_PROVIDER_ZONE; do
  [[ -n "${!v:-}" ]] || { echo "$v must be set" >&2; exit 2; }
done
WORK=$(mktemp -d)
export WORK
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=tests/live/do.sh
source "$(dirname "$0")/do.sh"
do_auth partner "$E2E_DO_PARTNER_TOKEN"
do_auth provider "$E2E_DO_PROVIDER_TOKEN"

do_delete_matching partner "$E2E_DO_PARTNER_ZONE" '.name | test("^(_acme-challenge\\.)?r[0-9]")'
do_delete_matching provider "$E2E_DO_PROVIDER_ZONE" '.type == "TXT" and (.name | test("^r[0-9]"))'
echo "sweep complete"
