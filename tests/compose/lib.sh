# shellcheck shell=bash
# Shared setup for the container-based tests (sourced, not executed).
#
# Provides: $WORK (temp dir), compose, steward, contract, ok, fail,
# setup_ssh (keys, known_hosts, authorized_keys) and the cleanup trap.
# Callers write $WORK/etc/config.yaml and then run `compose up`.

compose_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUBNET_PREFIX=${SUBNET_PREFIX:-172.30.99}
export WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"/{etc,steward,node1,node2,import}

compose() { docker compose -f "$compose_dir/compose.yml" "$@"; }
steward() { compose exec -T steward acme-steward "$@"; }
contract() { compose exec -T "$1" check-contract /srv/certs "${@:2}"; }

pass=0
ok()   { echo "PASS: $*"; pass=$((pass+1)); }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Functions run on exit before teardown (e.g. DNS cleanup).
cleanup_hooks=()
cleanup() {
  local rc=$?
  for h in "${cleanup_hooks[@]}"; do "$h" || true; done
  if [[ $rc -ne 0 ]]; then
    local f
    for f in "$WORK"/*.log; do
      [[ -e $f ]] || continue
      echo "--- $(basename "$f") (last 60 lines)"; tail -60 "$f"
    done
    echo "--- node1 sshd log"; compose logs --no-color node1 2>/dev/null | tail -20 || true
  fi
  if [[ -z "${KEEP:-}" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    echo "KEEP set: containers left running, WORK=$WORK"
  fi
  exit $rc
}
trap cleanup EXIT

# setup_ssh: steward client key, per-node host keys, known_hosts, and the
# production-style restricted authorized_keys on each node.
setup_ssh() {
  ssh-keygen -q -t ed25519 -N '' -C acme-steward -f "$WORK/steward/ssh_key"
  # The container user differs from the file owner, so ssh's own-key
  # permission check doesn't apply; the file only needs to be readable.
  chmod 0644 "$WORK/steward/ssh_key"
  : > "$WORK/steward/known_hosts"
  local n
  for n in node1 node2; do
    ssh-keygen -q -t ed25519 -N '' -C "$n" -f "$WORK/$n/ssh_host_ed25519_key"
    echo "$n $(cut -d' ' -f1,2 "$WORK/$n/ssh_host_ed25519_key.pub")" >> "$WORK/steward/known_hosts"
    echo "from=\"$SUBNET_PREFIX.10\",restrict,command=\"rrsync -wo /srv/certs\" $(cat "$WORK/steward/ssh_key.pub")" \
      > "$WORK/$n/authorized_keys"
  done
  # Readable by the container user, whatever the caller's umask.
  chmod 0644 "$WORK/steward/known_hosts"
}

# ssh_config_yaml: the ssh section shared by test configs.
ssh_config_yaml() {
  cat <<YAML
ssh:
  user: certdeploy
  key_file: /run/secrets/acme-steward/ssh_key
  known_hosts_file: /run/secrets/acme-steward/known_hosts
YAML
}
