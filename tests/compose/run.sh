#!/usr/bin/env bash
# End-to-end distribution test: real acme-steward image, real ssh/rsync,
# nodes restricted with rrsync exactly as the README's node-side contract
# describes. Certificates are imported (no CA needed).
#
#   tests/compose/run.sh            # KEEP=1 to leave containers running
set -euo pipefail

# shellcheck source=tests/compose/lib.sh
source "$(dirname "$0")/lib.sh"

# --- keys, config, certificates ----------------------------------------
setup_ssh

{ cat <<YAML
acme: {ca: letsencrypt-staging}
dns: {delegate_zone: delegate.invalid}
renewal: {keep_versions: 3}
YAML
  ssh_config_yaml
  cat <<YAML
clusters:
  - {name: c1, remote_dir: ., nodes: [{host: node1}, {host: node2}]}
  - {name: c2, remote_dir: ., nodes: [{host: node2}]}
certificates:
  - {name: alpha, domains: [alpha.test.invalid], clusters: [c1]}
  - {name: beta, domains: [beta.test.invalid], clusters: [c2]}
YAML
} > "$WORK/etc/config.yaml"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=Test-CA -keyout "$WORK/ca.key" -out "$WORK/import/ca.pem" 2>/dev/null
seq=0
# mkcert NAME DOMAIN -> writes $WORK/import/NAME-N.{key,pem}, echoes N
mkcert() {
  seq=$((seq+1))
  local base="$WORK/import/$1-$seq"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" \
    -keyout "$base.key" -out "$base.csr" 2>/dev/null
  openssl x509 -req -in "$base.csr" -CA "$WORK/import/ca.pem" -CAkey "$WORK/ca.key" \
    -days 30 -extfile <(echo "subjectAltName=DNS:$2") -out "$base.pem" 2>/dev/null
  chmod 0644 "$base.key"
}
# import NAME DOMAIN -> imports a fresh certificate, echoes its version
import() {
  mkcert "$1" "$2"
  steward import "$1" -cert "/import/$1-$seq.pem" -key "/import/$1-$seq.key" -chain /import/ca.pem 2>/dev/null
  compose exec -T steward readlink "/var/lib/acme-steward/certs/$1/current"
}

# --- bring up -------------------------------------------------------------
compose build -q
compose up -d --wait

# --- tests ----------------------------------------------------------------
a1=$(import alpha alpha.test.invalid)
b1=$(import beta beta.test.invalid)
steward push || fail "initial push"
[[ $(contract node1 alpha --version "$a1") == "$a1" ]] || fail "node1 alpha"
[[ $(contract node2 alpha --version "$a1") == "$a1" ]] || fail "node2 alpha"
[[ $(contract node2 beta --version "$b1") == "$b1" ]] || fail "node2 beta"
compose exec -T node1 test ! -e /srv/certs/beta || fail "beta delivered to node1, which is not in c2"
ok "initial push delivers each certificate only to its clusters, meeting the contract"

out=$(steward push 2>&1) || fail "repeat push"
grep -q '"event":"push.node_updated"' <<<"$out" && fail "repeat push transferred data: $out"
grep -q '"event":"push.node_current"' <<<"$out" || fail "no node_current events: $out"
ok "repeat push is a no-op"

out=$(compose exec -T steward ssh -F none -i /run/secrets/acme-steward/ssh_key -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/secrets/acme-steward/known_hosts \
  certdeploy@node1 id 2>&1) && fail "arbitrary command succeeded: $out"
grep -q 'uid=' <<<"$out" && fail "command ran on node: $out"
ok "steward key cannot run commands on a node ($(tail -1 <<<"$out"))"

compose exec -T intruder acme-steward import alpha -cert "/import/alpha-1.pem" -key "/import/alpha-1.key" 2>/dev/null
out=$(compose exec -T intruder acme-steward push 2>&1) && fail "push from unauthorised address succeeded"
grep -q 'push.node_failed.*Permission denied (publickey)' <<<"$out" || fail "intruder: $out"
ok "nodes reject the key from any other address"

sed -i 's/^node1 /nodeX /' "$WORK/steward/known_hosts"
out=$(steward push -cluster c1 2>&1) && fail "push to node with unknown host key succeeded"
grep -q 'Host key verification failed\|No ED25519 host key is known' <<<"$out" || fail "host key: $out"
sed -i 's/^nodeX /node1 /' "$WORK/steward/known_hosts"
ok "host keys are verified"

compose stop node2 >/dev/null
a2=$(import alpha alpha.test.invalid)
out=$(steward push 2>&1) && fail "push with a node down reported success"
grep -q '"event":"push.node_failed".*"node":"node2"\|"node":"node2".*"event":"push.node_failed"' <<<"$out" || fail "node2 failure not logged: $out"
[[ $(contract node1 alpha --version "$a2") == "$a2" ]] || fail "node1 not updated while node2 down"
steward status | grep -E '^c1 +node2 +alpha +stale' >/dev/null || fail "status does not show node2 stale: $(steward status)"
ok "a down node doesn't block the others and shows as stale"

compose start node2 >/dev/null
compose up -d --wait node2 >/dev/null
steward push || fail "push after node2 restart"
[[ $(contract node2 alpha --version "$a2") == "$a2" ]] || fail "node2 did not catch up"
steward status | grep -E '^c1 +node2 +alpha +current' >/dev/null || fail "status after catch-up: $(steward status)"
ok "a returning node catches up"

for _ in 1 2 3; do a_last=$(import alpha alpha.test.invalid); done
steward push || fail "push after more versions"
for n in node1 node2; do
  [[ $(contract $n alpha --version "$a_last" --max-versions 3) == "$a_last" ]] || fail "$n pruning"
  compose exec -T $n test ! -e "/srv/certs/alpha/$a1" || fail "$n still has $a1"
done
[[ $(contract node2 beta --version "$b1") == "$b1" ]] || fail "beta disturbed by alpha pruning"
ok "pruned versions are deleted from nodes; other certificates untouched"

echo "all $pass distribution tests passed"
