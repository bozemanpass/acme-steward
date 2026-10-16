#!/bin/sh
# Installed as /usr/local/bin/acme-steward, in front of the real binary, so
# the entrypoint, HEALTHCHECK and `exec ... acme-steward` all go through it.
#
# Deployment tools mount the data volume owned by root or by the host user,
# and can't always set fsGroup. Started as root, this hands the data
# directory to the acme user, then runs acme-steward as that user.
set -eu
bin=/usr/local/libexec/acme-steward/acme-steward
if [ "$(id -u)" != 0 ]; then
	exec "$bin" "$@"
fi
data="${ACME_STEWARD_DATA_DIR:-/var/lib/acme-steward}"
mkdir -p "$data"
if [ "$(stat -c %u "$data")" != "$(id -u acme)" ]; then
	chown -R acme:acme "$data"
fi
HOME=/var/lib/acme-steward
export HOME
exec setpriv --reuid=acme --regid=acme --init-groups --no-new-privs -- "$bin" "$@"
