# acme-steward

Obtains and renews TLS server certificates for services hosted on a
**cluster** of servers, and pushes the certificate files to every node.

Single-server tools (Caddy, cert-manager, certbot) use HTTP-01 on the server
that serves the site. On a cluster behind a floating IP that would mean
deciding which node owns the IP and copying files between nodes.
acme-steward runs on a separate host instead. It:

1. requests and renews certificates from an ACME CA (Let's Encrypt) with
   **DNS-01** challenges, using [lego](https://go-acme.github.io/lego/) as a library;
2. supports **CNAME delegation**, so the hostnames can live in DNS zones we
   don't control (e.g. partners' zones). Each hostname's
   `_acme-challenge` name is CNAMEd once into a dedicated delegate zone
   hosted at DigitalOcean, and challenge records are written only there;
3. **pushes** the PEM files with `rsync` over `ssh` to each node of the
   clusters configured for that certificate.

Installing the certificates into the HTTP server on each node (reloads,
restarts, rolling updates) is **out of scope**. acme-steward delivers files
in a defined layout (see [Node-side contract](#node-side-contract)), and
what happens after that is up to node-side tooling.

There is no web UI or API. Configuration comes from a YAML file and
environment variables, and status goes to a structured (JSON) log.

```
 partner zone                                    delegate zone (DigitalOcean)
 _acme-challenge.sync.partner.com  CNAME  -->  sync-partner-com-k3x9q2ab.acme-delegate.example.net
                                                   ^  TXT written/removed per challenge
                                                   |  DigitalOcean API
                                    +--------------+---------------+
                                    | acme-steward                 |
                                    |  ACME account key, DO token  |
                                    |  SSH key, known_hosts        |
                                    +--------------+---------------+
                                                   |  rsync over ssh (restricted account)
                         +-------------------+-----+-------------+
                       node1               node2       ...     nodeN
```

## Commands

```
acme-steward [-config FILE] <command>

  run                      run continuously: renew when due, push to all nodes
  cycle                    run one renew+push cycle and exit (for cron / CronJob)
  renew [-force] [CERT...] renew certificates that are due (all named, with -force)
  push [-cluster C]...     push current certificates to cluster nodes
  import CERT -cert F -key F [-chain F]
                           install an existing certificate (e.g. during migration)
  status                   show certificate and per-node delivery status
  onboard CERT|DOMAIN      print forwardable DNS instructions for the partner
  check [-wait D] [-v] [CERT|DOMAIN...]
                           verify the partner's DNS: READY / NOT READY per step
  account                  register the ACME account if needed; print its URI
  validate                 validate the configuration file
  healthcheck              non-zero exit if the daemon hasn't completed a recent cycle
```

Each cycle:

- **Renews** a certificate when it has none yet, when its domains, key type
  or profile changed, or when it reaches its renewal time. The renewal time
  comes from the CA's [ARI](https://www.rfc-editor.org/rfc/rfc9773.html)
  window. If the CA doesn't offer ARI, renewal happens once
  `renew_remaining` (default 1/3) of the certificate's lifetime is left.
  Every renewal generates a new private key.
- **Reconciles** every node: each configured node is brought up to date on
  every cycle, not only after a renewal. A node that was down, or one just
  added, catches up on the next cycle. Unchanged files cost almost nothing to
  re-check.
- **Warns** in the log when a certificate is in the last `warn_remaining`
  (default 1/6) of its lifetime. That only happens if renewals have been
  failing.

Safety limits on renewal:

- **Backoff:** after a failed order, retries wait `retry_min`, doubling up to
  `retry_max`.
- **Issuance guard:** no more than `max_issues_per_week` automatic issuances
  per certificate, which stops a bug from looping into the CA's rate limits.
  `renew -force` bypasses both.
- **Delegation guard:** challenge records are written only inside the
  delegate zone. If a hostname's `_acme-challenge` CNAME is missing or points
  elsewhere, the order is refused before any validation is attempted, so a
  misconfigured partner doesn't use up the CA's failed-validation limit.

## Configuration

See [`examples/config.yaml`](examples/config.yaml) for every option.

| Environment variable | Purpose |
|---|---|
| `ACME_STEWARD_CONFIG` | config file (default `/etc/acme-steward/config.yaml`) |
| `ACME_STEWARD_DATA_DIR` | persistent data directory (default `/var/lib/acme-steward`) |
| `DO_AUTH_TOKEN` / `DO_AUTH_TOKEN_FILE` | DigitalOcean API token, or a file containing it (needed by `run`, `cycle`, `renew`) |
| `ACME_STEWARD_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `ACME_STEWARD_LOG_FORMAT` | `json` (default) or `text` |

The data directory holds the ACME account key and every issued private key.
It must be persistent and private (it is created mode 0700):

```
account/account.key, account.json      ACME account
certs/<name>/<version>/...             issued certificates (mirrored to nodes)
certs/<name>/current -> <version>
state/                                 renewal and push state
heartbeat, lock
```

Only one instance may run against a data directory at a time, and a lock
file enforces this.

## Initial setup

1. **Delegate zone.** Register a dedicated domain (e.g.
   `acme-delegate.example.net`) and host it at DigitalOcean, in a
   **DigitalOcean account that contains nothing else**. DigitalOcean tokens
   can't be limited to a single domain, and whoever holds the token can get
   certificates issued for every delegated hostname. Create a token with
   write access to domains.

   acme-steward keeps a **placeholder TXT record** at every delegate label
   (value `acme-steward placeholder: ...`); don't delete these. They exist
   because DigitalOcean's nameservers cache "no such name" answers for 30
   minutes. Without a placeholder, a label has no records between orders,
   and the lookups lego makes just before creating the challenge record
   would cache NXDOMAIN and hide the new record until the order timed out.
   With the placeholder the name always exists, and changes to its TXT
   records show up within about 40 seconds. Placeholders are created
   automatically before the first order for a label, with a 90-second wait
   for publication, and re-checked daily.

   For the same reason, after lego sees the new challenge record, acme-steward
   waits `dns.propagation_settle` (default 90s) before letting the CA
   validate. The CA validates from several locations, and some may reach
   DigitalOcean nameserver instances that are still serving the previous
   TXT set for up to about 40 seconds.

2. **ACME account.** Set `acme.accept_terms: true` to accept the CA's terms;
   the account is registered on first use. Start with
   `ca: letsencrypt-staging` and switch to `letsencrypt` once everything
   works. **Back up `account/account.key`**: a partner who pins issuance to
   our account with CAA `accounturi` can only be renewed with that key.
3. **SSH.** Generate a key pair for acme-steward. Collect the nodes' host
   keys into a `known_hosts` file (`ssh-keyscan`, verified out of band).
   Host keys are always checked strictly. Set up each node as described
   under [Node-side contract](#node-side-contract).

## Partner onboarding

Partners' DNS staff are often reached only indirectly, through several
people forwarding email. So `onboard` produces a complete set of
instructions that can be forwarded as-is, and `check` verifies the result
and states exactly what is still missing.

1. Add the certificate to the config (name, domains, clusters). Run
   `acme-steward account` once to register the ACME account, so the
   instructions can include the optional CAA pinning step.
2. Run `acme-steward onboard <cert> > instructions.txt` and send the file.
   It looks up the partner's DNS as it is now, and writes plain ASCII text
   wrapped at 72 columns that survives forwarding. It contains:
   - each record to add, set out the way DNS control panels ask for it
     (zone-relative name, type, value, TTL), with notes on full names and
     trailing dots;
   - warnings for things it found that would get in the way, such as
     left-over `_acme-challenge` TXT records or a CNAME pointing
     elsewhere;
   - CAA: "no change needed"; a **required** CAA record if their current
     CAA would block the CA (added at the hostname itself, so the rest of
     their domain is unaffected); or an **optional, recommended** record
     pinning issuance to our ACME account (see `partner_instructions.caa_pin`);
   - a short explanation of what the delegation does and does not give us,
     for their security review;
   - `dig` commands and their expected output, so they can verify their own
     change.

   Steps already in place are marked "ALREADY DONE", so re-running `onboard`
   for a follow-up email lists only what is still outstanding.

   The CNAME label is derived from the hostname: a readable prefix plus a
   hash, which keeps it unique and within the 63-octet label limit. It
   never changes, and a fixed label can be pinned per domain with
   `delegate_labels`.
3. Run `acme-steward check <cert>` (add `-wait 2h` to keep polling). It
   prints READY or NOT READY, with each step's status in the same terms
   as the instructions, e.g.

   ```
   partner-a: NOT READY
     step 1, Add a CNAME record for sync.partner.com: PENDING: the record is in place on the
       partner's DNS servers but not yet visible everywhere; waiting for caches to expire
     step 2, Allow Let's Encrypt in the CAA records for sync.partner.com: done
   ```

   It checks the CNAME both at the partner's own nameservers and through
   public resolvers. `-v` adds the full per-resolver detail, including
   whether the hostname's A/AAAA records match the cluster's `addresses`.
4. Once it is READY, the certificate is issued and pushed on the next
   cycle, or straight away with `renew <cert>` followed by `push`.

To **migrate** a hostname that already has a certificate from another CA,
`import` that certificate and key so the nodes get it in the standard
layout straight away. The next cycle replaces it with an ACME certificate
if its names or key type differ from the configuration, or if it is due
for renewal.

To **offboard** a partner, remove the certificate from the config. It stops
being renewed, but the files already delivered stay on the nodes. Ask the
partner to remove the CNAME, and never reuse the label for someone else.

## Node-side contract

Each node needs:

- an account for acme-steward (e.g. `certdeploy`) whose `authorized_keys`
  entry only allows rsync writes into one directory:

  ```
  from="<steward IP>",restrict,command="rrsync -wo /srv/certs" ssh-ed25519 AAAA... acme-steward
  ```

  The cluster's `remote_dir` is then relative to that directory (e.g. `.`).
  The directory must already exist.
- `rsync` installed (`rrsync` ships with rsync 3.2.4+).

Delivered layout under `remote_dir`, one directory per certificate the
cluster carries:

```
<name>/current -> <version>          symlink, updated last
<name>/<version>/cert.pem            leaf certificate
<name>/<version>/chain.pem           intermediate(s)
<name>/<version>/fullchain.pem       cert.pem + chain.pem
<name>/<version>/privkey.pem         private key (mode 0600)
<name>/<version>/manifest.json       domains, serial, validity, sha256 of each file
```

Guarantees:

- A version directory never changes after it is created.
- `current` is updated only after a separate, earlier rsync has finished
  transferring the whole version directory. Node-side tooling can therefore
  trust that `current` always points at a complete set of files.
- At most `keep_versions` versions are kept, and older ones are deleted
  from the nodes. Node-side tooling should use `current/...` (or copy the
  files), not a pinned version path.
- Nothing outside `<remote_dir>/<name>/` is touched.
- A node that belongs to several clusters is pushed to one session at a
  time, because rrsync refuses concurrent sessions on the same directory.

Node-side tooling detects a new version by comparing `current` (or
`manifest.json`'s `version`) with what it last installed, then validates
the files against the manifest, installs them and reloads the server.

## Logging and status

Logs are JSON lines on stderr. Every record carries an `event` field so
that monitoring (or a future, separately hosted UI) can parse it. Main
events:

| Event | Level | Meaning |
|---|---|---|
| `cert.issuing` / `cert.issued` | info | order started / certificate saved (`version`, `serial`, `not_after`) |
| `cert.issue_failed` | error | order failed (`error`, `failures`, `next_attempt`) |
| `cert.renewal_scheduled` | info | renewal time chosen (`renew_at`, `source`: `ari` or `lifetime`) |
| `cert.rate_guard` | error | renewal due but blocked by `max_issues_per_week` |
| `cert.ari_failed` | warn | ARI query failed; lifetime schedule used |
| `cert.expiry_warning` / `cert.expired` | warn / error | renewals have been failing |
| `cert.missing` | warn | configured certificate not yet issued |
| `push.node_updated` | info | new files delivered to a node |
| `push.node_failed` | error | node unreachable or rsync failed (`consecutive_failures`) |
| `push.node_current` | debug | node already up to date |
| `dns.placeholder_created` / `dns.placeholder_failed` | info / warn | placeholder TXT record created at a delegate label / could not be checked |
| `account.registered` | info | ACME account created (`account_uri`) |
| `onboard.check` | info | result of a `check` run |
| `steward.start` / `steward.stop` / `steward.locked` | info / error | daemon lifecycle |

`acme-steward status` prints the same information as a table, read from
the state files.

## Deployment notes

acme-steward is designed to run in a container (Docker or Kubernetes). Build the
image with:

```
docker build -f Containerfile -t acme-steward .
```

- The image (Debian slim with `ssh`, `rsync` and CA certificates) runs as
  uid 10001 with `acme-steward run` as the default command.
- ssh refuses a private key file that is owned by the running user and
  readable by others. A secret mounted as root-owned and group-readable
  (e.g. Kubernetes `defaultMode: 0440` with `fsGroup: 10001`) works.
- Mount a persistent volume at the data directory. Mount the DO token, SSH
  key and `known_hosts` as secrets (`DO_AUTH_TOKEN_FILE`,
  `ssh.key_file`, `ssh.known_hosts_file`).
- Run **one replica**; on Kubernetes use the `Recreate` strategy. Use
  `acme-steward healthcheck` as the liveness probe, with a start period
  long enough for initial issuance.
- Outbound access is needed to the CA, the DigitalOcean API, public DNS
  resolvers (port 53) and the nodes' SSH ports. No inbound access is
  needed.
- The `resolvers` setting sends lego's CNAME and propagation lookups to
  public resolvers instead of in-cluster DNS, which can serve stale
  answers.

## Security considerations

- The **DigitalOcean token** lets its holder get certificates issued for
  every delegated hostname. Keep it in a dedicated DigitalOcean account
  holding only the delegate zone, and treat the steward host as sensitive.
- The **data directory** holds every private key and the ACME account key.
- Partners can restrict issuance to our ACME account with CAA
  `accounturi` (RFC 8657). Watching Certificate Transparency logs for
  partner hostnames will reveal unexpected issuance.
- **Nodes hold no central credentials.** The steward's SSH key can only
  write into the staging directory, and only from the steward's address.
- Secrets never appear in logs.

## Development and testing

```
go test ./...                               # unit tests (uses local rsync)

go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
go test -tags e2e ./internal/e2e            # issuance against Pebble

tests/compose/run.sh                        # distribution, in containers
```

- **Issuance (Pebble):** real lego issuance against Pebble, Let's Encrypt's
  test CA. It uses a fake DigitalOcean API and an in-process DNS server
  that holds both a "partner" zone (containing the delegation CNAME) and
  the delegate zone. It checks that challenge records are written only
  under the delegate label.
- **Distribution (compose):** builds the real image from `Containerfile`
  and runs it alongside two test nodes. Each node runs sshd with a
  `certdeploy` account restricted exactly as in the
  [Node-side contract](#node-side-contract) (`from=`, `restrict`,
  `rrsync -wo`). The tests import certificates, push, and check the
  delivered tree on each node with `check-contract`. They cover:
  - each certificate reaches only its own clusters;
  - a repeat push is a no-op;
  - the key cannot run commands on a node, and is rejected from any
    other address;
  - host keys are verified;
  - a down node doesn't block the others and catches up when it returns;
  - pruned versions are deleted from the nodes.

  Set `KEEP=1` to leave the containers running afterwards.

All three run in GitHub Actions (`.github/workflows/test.yml`). See [docs/testing.md](docs/testing.md) for how
each tier works, the live test against Let's Encrypt staging and
real DigitalOcean zones, and notes on CAA.

## Possible future work

- **DNS-PERSIST-01**, a proposed challenge type that uses a single
  persistent TXT record authorising our ACME account. It would remove the
  per-renewal DNS writes and the DigitalOcean token altogether. It could be
  added as a per-certificate challenge method once CAs support it.
- A `revoke` command, and an `offboard` command that removes a partner and
  revokes their certificate.
- Kubernetes manifests.
