#!/bin/sh
# Install the host key and authorized_keys mounted at /keys with the
# ownership and modes sshd insists on, then run sshd.
set -e
install -m 0600 /keys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
install -m 0644 /keys/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
install -d -o certdeploy -g certdeploy -m 0700 /home/certdeploy/.ssh
install -o certdeploy -g certdeploy -m 0600 /keys/authorized_keys /home/certdeploy/.ssh/authorized_keys
rm -f /run/sshd.pid
exec /usr/sbin/sshd -D -e
