#!/usr/bin/env bash
# Live end-to-end test: Let's Encrypt staging + real DigitalOcean DNS +
# distribution to container nodes. See docs/testing.md, section 4.
#
# Required environment:
#   E2E_DO_PARTNER_TOKEN, E2E_DO_PARTNER_ZONE    the "partner" account/zone
#   E2E_DO_PROVIDER_TOKEN, E2E_DO_PROVIDER_ZONE  our delegate account/zone
#
# The partner token is used only by this script, which plays the partner.
# The steward container receives only the provider token.
set -euo pipefail

for v in E2E_DO_PARTNER_TOKEN E2E_DO_PARTNER_ZONE E2E_DO_PROVIDER_TOKEN E2E_DO_PROVIDER_ZONE; do
  [[ -n "${!v:-}" ]] || { echo "$v must be set (see docs/testing.md)" >&2; exit 2; }
done
for tool in docker jq curl dig ssh-keygen; do
  command -v $tool >/dev/null || { echo "$tool is required" >&2; exit 2; }
done

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/compose/lib.sh
source "$here/../compose/lib.sh"
# shellcheck source=tests/live/do.sh
source "$here/do.sh"

PZ=$E2E_DO_PARTNER_ZONE
DZ=$E2E_DO_PROVIDER_ZONE
# A name never used before, so no resolver can have a cached negative answer.
RUN=r${GITHUB_RUN_ID:-$(date +%s)}${GITHUB_RUN_ATTEMPT:+-$GITHUB_RUN_ATTEMPT}
CLUSTER_ADDR=192.0.2.10 # TEST-NET; the A record only feeds the address check

# CAA accounturi pinning can't be tested here: DigitalOcean's API rejects
# CAA values with RFC 8657 parameters. See docs/testing.md.
declare -A HOST=(
  [main]=$RUN.$PZ            # delegated; baseline zone CAA permits LE
  [otherca]=$RUN-ca.$PZ      # delegated; CAA allows another CA only
  [nocname]=$RUN-none.$PZ    # partner never adds the CNAME
)
echo "run $RUN: partner zone $PZ, delegate zone $DZ"

do_auth partner "$E2E_DO_PARTNER_TOKEN"
do_auth provider "$E2E_DO_PROVIDER_TOKEN"
partner_records=()

cleanup_dns() {
  echo "--- cleaning up DNS for $RUN"
  for id in "${partner_records[@]}"; do do_delete_record partner "$PZ" "$id" || true; done
  # Challenge TXT records are acme-steward's to remove; delete leftovers
  # only so a failed run doesn't leave clutter (they are reported below).
  do_delete_matching provider "$DZ" ".type == \"TXT\" and (.name | startswith(\"$RUN\"))"
}
cleanup_hooks+=(cleanup_dns)

log() { echo; echo "=== $*"; }

# fail_ca MESSAGE LOG...: fail, first explaining any errors the CA itself
# returned in LOG. Those say nothing about acme-steward, and the follow-up
# differs; see docs/testing.md, "When the CA is the problem".
fail_ca() {
  local msg=$1; shift
  local busy limited
  busy=$(grep -ohE 'acme: error: 5[0-9]{2} :: [^"\\]*' "$@" 2>/dev/null | sort -u | head -3 || true)
  limited=$(grep -ohE 'acme: error: 429 :: [^"\\]*' "$@" 2>/dev/null | sort -u | head -3 || true)
  if [[ -n $busy ]]; then
    cat >&2 <<EOF

*** Let's Encrypt staging returned server errors (5xx) during this step:
$busy
*** The CA was overloaded or down; this is most likely not an acme-steward
*** failure. Re-run once staging recovers (https://letsencrypt.status.io/)${GITHUB_RUN_ID:+:
***   gh run rerun $GITHUB_RUN_ID --failed}
EOF
    [[ -n ${GITHUB_ACTIONS:-} ]] &&
      echo "::error title=Let's Encrypt staging unavailable::CA returned 5xx; re-run once staging recovers (see docs/testing.md)"
  fi
  if [[ -n $limited ]]; then
    cat >&2 <<EOF

*** Let's Encrypt staging rate-limited this run (429):
$limited
*** A re-run won't help until the limit's window passes. The message names
*** the limit; see docs/testing.md, "When the CA is the problem".
EOF
    [[ -n ${GITHUB_ACTIONS:-} ]] &&
      echo "::error title=Let's Encrypt staging rate limit::CA returned 429; see docs/testing.md before re-running"
  fi
  fail "$msg"
}

# --- setup ------------------------------------------------------------------
setup_ssh
umask 022
printf '%s' "$E2E_DO_PROVIDER_TOKEN" > "$WORK/steward/do_token"
chmod 0644 "$WORK/steward/do_token" # readable by the container user; see lib.sh
export STEWARD_DO_TOKEN_FILE=/run/secrets/acme-steward/do_token

write_config() { # write_config RESOLVERS_YAML
  cat <<YAML
acme: {ca: letsencrypt-staging, accept_terms: true}
dns:
  delegate_zone: $DZ
  propagation_timeout: 10m
  $1
renewal: {keep_versions: 3}
partner_instructions: {organization: acme-steward live test, caa_pin: optional}
YAML
  ssh_config_yaml
  cat <<YAML
clusters:
  - {name: c1, remote_dir: ., addresses: [$CLUSTER_ADDR], nodes: [{host: node1}, {host: node2}]}
certificates:
  - {name: main, domains: [${HOST[main]}, "*.${HOST[main]}"], clusters: [c1]}
  - {name: otherca, domains: [${HOST[otherca]}], clusters: [c1]}
  - {name: nocname, domains: [${HOST[nocname]}], clusters: [c1]}
YAML
}
write_config "" > "$WORK/etc/config.yaml"

compose build -q
compose up -d --wait steward node1 node2

# --- 1. account ---------------------------------------------------------------
log "ACME account"
ACCOUNT=$(steward account 2>>"$WORK/steward.log") || { cat "$WORK/steward.log"; fail_ca "account registration" "$WORK/steward.log"; }
[[ $ACCOUNT == https://acme-staging-v02.api.letsencrypt.org/* ]] || fail "unexpected account URI $ACCOUNT"
ok "registered staging account $ACCOUNT"

# IMPORTANT: nothing may query a per-run name before its record exists and
# has been published. Resolvers -- including DigitalOcean's own
# authoritative servers -- cache "no such name" for the zone's negative TTL
# (30 minutes), which would hide the record for that long.

# --- 2. play the partner ------------------------------------------------------
log "partner adds the required records"
# `records` prints the CNAMEs without any DNS lookups.
declare -A TARGET=()
for c in main otherca; do
  line=$(steward records $c 2>>"$WORK/steward.log")
  TARGET[$c]=$(awk '{print $3}' <<<"$line")
  [[ ${TARGET[$c]} == *.$DZ. ]] || fail "$c: CNAME target '${TARGET[$c]}' is not in $DZ"
done
rel() { echo "${1%.$PZ}"; }
add() { # add JSON
  local id
  id=$(do_add_record partner "$PZ" "$1") || fail "creating partner record $1"
  partner_records+=("$id")
}
for c in main otherca; do
  add "{\"type\":\"CNAME\",\"name\":\"_acme-challenge.$(rel ${HOST[$c]})\",\"data\":\"${TARGET[$c]}\",\"ttl\":30}"
done
add "{\"type\":\"A\",\"name\":\"$(rel ${HOST[main]})\",\"data\":\"$CLUSTER_ADDR\",\"ttl\":30}"
caa() { # caa CERT VALUE  (DigitalOcean's API wants the issuer as an FQDN)
  add "$(jq -nc --arg n "$(rel ${HOST[$1]})" --arg v "$2" '{type:"CAA",name:$n,data:$v,flags:0,tag:"issue",ttl:30}')"
}
caa otherca "pki.goog."
ok "created ${#partner_records[@]} partner records via the partner account"

# Give DigitalOcean time to publish before the first query (observed: under
# 35s), then confirm every nameserver serves the records.
sleep 60
do_ns=()
for ns in ns1 ns2 ns3; do do_ns+=("$ns.digitalocean.com"); done
wait_auth() { # wait_auth NAME TYPE
  local ns
  for ns in "${do_ns[@]}"; do
    for _ in $(seq 12); do
      [[ -n $(dig +short +norec "$2" "$1" @"$ns") ]] && continue 2
      sleep 10
    done
    fail "$2 $1 not served by $ns 3 minutes after creation"
  done
}
for c in main otherca; do wait_auth "_acme-challenge.${HOST[$c]}" CNAME; done
wait_auth "${HOST[otherca]}" CAA
ok "records served by all DigitalOcean nameservers"

# --- 3. instructions ------------------------------------------------------------
log "onboarding instructions"
steward onboard main > "$WORK/onboard-main.txt" 2>>"$WORK/steward.log"
echo "--- instructions for main, as the partner would now receive them:"
cat "$WORK/onboard-main.txt"
flat=$(tr -s ' \n' ' ' < "$WORK/onboard-main.txt")
grep -q "STEP 1 (ALREADY DONE - no action needed): Add a CNAME record for ${HOST[main]}" <<<"$flat" ||
  fail "onboard does not recognise the CNAME as done"
grep -q '(REQUIRED)' <<<"$flat" && fail "onboard still lists required steps"
grep -qE 'no CAA change is required|no change needed' <<<"$flat" || fail "onboard should say no CAA change is needed"
caa_value_of() { awk '/Tag: +issue$/ {getline; sub(/^ *Value: +/, ""); print; exit}' "$WORK/onboard-$1.txt"; }
PIN_VALUE=$(caa_value_of main)
[[ $PIN_VALUE == "letsencrypt.org; accounturi=$ACCOUNT; validationmethods=dns-01" ]] || fail "pin value: $PIN_VALUE"
ok "onboard sees the delegation as done and offers pinning to our account"

# --- 4. verification ------------------------------------------------------------
log "check"
steward check -wait 15m main || fail "main not READY"
ok "check reports READY for correctly configured partners"

expect_not_ready() { # expect_not_ready CERT PATTERN
  local out
  out=$(steward check "$1" 2>/dev/null) && fail "$1 unexpectedly READY"
  grep -q "$2" <<<"$out" || fail "$1: expected '$2' in: $out"
}
expect_not_ready otherca "does not permit"
expect_not_ready nocname "no CNAME record"
ok "check reports NOT READY with the right reason for each misconfiguration"

# --- 5. issuance and distribution ---------------------------------------------
log "cycle 1"
steward cycle 2> "$WORK/cycle1.log" || true
events() { # events LOG EVENT CERT
  grep '^{' "$1" | jq -c "select(.event == \"$2\" and .cert == \"$3\")" || true
}
[[ -n $(events "$WORK/cycle1.log" cert.issued main) ]] || { cat "$WORK/cycle1.log"; fail_ca "main not issued" "$WORK/cycle1.log"; }
ok "main (base + wildcard) issued by staging"

e=$(events "$WORK/cycle1.log" cert.issue_failed otherca)
grep -qi caa <<<"$e" || { cat "$WORK/cycle1.log"; fail_ca "otherca: expected a CAA refusal, got: $e" "$WORK/cycle1.log"; }
ok "the CA refuses issuance where CAA forbids it"

e=$(events "$WORK/cycle1.log" cert.issue_failed nocname)
grep -q "does not resolve via CNAME into delegate zone" <<<"$e" || fail "nocname: $e"
ok "the delegation guard refuses a hostname without the CNAME"

manifest() { compose exec -T steward cat "/var/lib/acme-steward/certs/$1/current/manifest.json"; }
issuer=$(manifest main | jq -r .issuer)
[[ $issuer == *STAGING* ]] || fail "issuer '$issuer' is not a staging intermediate"
[[ $(manifest main | jq -r '.domains | sort | join(",")') == "*.${HOST[main]},${HOST[main]}" ]] || fail "main domains"
v1=$(manifest main | jq -r .version)
for n in node1 node2; do
  [[ $(contract $n main --version "$v1") == "$v1" ]] || fail "$n main contract"
  compose exec -T $n test ! -e /srv/certs/otherca || fail "$n has otherca"
done
ok "certificates ($issuer) delivered to both nodes meeting the contract"

# Only acme-steward's permanent placeholders may remain at this run's labels.
txt=$(do_list_records provider "$DZ" | jq -c "[.[] | select(.type == \"TXT\" and (.name | startswith(\"$RUN\")))]")
left=$(jq -r '.[] | select(.data | contains("acme-steward placeholder") | not) | "\(.name) \(.data)"' <<<"$txt")
[[ -z $left ]] || fail "challenge TXT records left in $DZ: $left"
[[ $(jq length <<<"$txt") -eq 3 ]] || fail "expected one placeholder per label, got: $txt"
ok "acme-steward removed its challenge records from $DZ, leaving one placeholder per label"

# --- 6. renewal scheduling ----------------------------------------------------------
log "cycle 2"
steward cycle 2> "$WORK/cycle2.log" || true
[[ -z $(grep '^{' "$WORK/cycle2.log" | jq -c 'select(.event == "cert.issued")') ]] || fail "second cycle reissued"
src=$(compose exec -T steward cat /var/lib/acme-steward/state/certs/main.json | jq -r .renew_at_source)
[[ $src == ari ]] || fail "renewal schedule source is '$src', expected ari"
ok "second cycle schedules renewal from staging's ARI and does not reissue"

# --- 7. forced renewal -------------------------------------------------------------------
log "forced renewal"
steward renew -force main 2> "$WORK/renew.log" || { cat "$WORK/renew.log"; fail_ca "forced renewal" "$WORK/renew.log"; }
steward push 2>/dev/null || fail "push after renewal"
v2=$(manifest main | jq -r .version)
[[ $v2 != "$v1" ]] || fail "no new version"
for n in node1 node2; do
  [[ $(contract $n main --version "$v2") == "$v2" ]] || fail "$n main after renewal"
  compose exec -T $n test -d "/srv/certs/main/$v1" || fail "$n lost the previous version"
done
ok "forced renewal reaches the nodes; the previous version is retained"

echo
echo "all $pass live tests passed"
