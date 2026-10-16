# Testing acme-steward

This document describes how acme-steward is tested: what each tier proves,
how its plumbing works, and what is needed to run it. It is also meant as a
reference for building similar tests in other projects.

| Tier | What it exercises | Runs | Needs secrets |
|---|---|---|---|
| [Unit](#1-unit-tests) | logic: config, labels, store, renewal scheduling, push grouping, DNS checks | every PR | no |
| [Issuance (Pebble)](#2-issuance-against-pebble) | real lego issuance via CNAME delegation, against a local test CA | every PR | no |
| [Distribution (compose)](#3-distribution-in-containers) | real image, real ssh/rsync to restricted nodes | every PR | no |
| [Live](#4-live-test-lets-encrypt-staging--digitalocean) | Let's Encrypt staging + real DigitalOcean DNS + distribution | main, weekly, manual | yes |

The first three are in `.github/workflows/test.yml`; the live tier is in
`live.yml` (plus `live-sweep.yml` for DNS cleanup). Each tier replaces one
more fake with the real thing. The live tier is the only one that talks to
outside services.

---

## 1. Unit tests

```
go test -race ./...
```

Plain Go tests. Some points that aren't obvious from the code:

- **Fake ssh.** `internal/testutil.FakeSSH` writes a script that rsync uses
  as its `-e` command. The script drops the ssh arguments and runs the
  "remote" rsync locally, so push logic is tested with real rsync but
  without sshd. If a named file exists, the script fails like an
  unreachable host, which simulates a node going down.
- **Fake issuer.** Steward tests replace the lego issuer with one that mints
  certificates from a throwaway CA (`testutil.Cert`). Time is a settable
  clock, so renewal scheduling, backoff, the weekly issuance guard and
  expiry warnings can be tested by advancing it.
- **Concurrency.** `TestPushSharedHost` uses a fake ssh that fails if two
  sessions to the same host overlap. This guards against the rrsync
  locking problem described in [§3](#lessons-learned).
- **DNS.** `internal/dnscheck` tests run an in-process `miekg/dns` server
  that acts as both recursive resolver and authoritative server. They
  cover CNAME present/missing/wrong, left-over TXT records, and CAA tree
  climbing, `issuewild`, `accounturi` (including a set where only the
  second record permits us) and `validationmethods`.
- **Partner instructions.** `internal/onboard` tests build DNS states
  directly and check the steps and rendered text for each scenario: fresh,
  CAA blocks, pinned to another account, left-over TXT, wrong target,
  propagating, complete, pin required, and wildcard `issuewild`. They also
  check that output is ASCII and that prose wraps at 72 columns.

---

## 2. Issuance against Pebble

```
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
go test -tags e2e ./internal/e2e          # PEBBLE_BIN=... if not on PATH
```

[Pebble](https://github.com/letsencrypt/pebble) is Let's Encrypt's
small test CA. It implements the ACME protocol, including ARI and
profiles, and validates challenges against a DNS server you choose.

```
                       +-----------------------------+
                       | in-process DNS server       |
                       |  partner.test               |
                       |   _acme-challenge.svc  CNAME --+
                       |  delegate.test               |  |
                       |   <label>  TXT  (dynamic)  <---+
                       +------^----------------^------+
          CNAME lookups,      |                | TXT validation
          zone (SOA) lookup   |                |
 +-----------------------+    |        +-------+------+
 | acme-steward (in test)|----+        | Pebble       |
 |  real lego client     |------------>| (subprocess) |
 |                       |   ACME      +--------------+
 |  DO provider ---------+---> fake DigitalOcean API (httptest)
 +-----------------------+         writes TXT into the DNS server
```

How it works:

- **DNS server.** It holds both zones, answers SOA/NS for the zone apexes,
  and follows CNAMEs like a recursive resolver (CNAME and target TXT are
  returned together). It listens on UDP and TCP because Pebble queries
  over TCP. Pebble's own `pebble-challtestsrv` can't be used, because it
  doesn't answer SOA/NS queries and lego needs them to find the zone.
- **Fake DigitalOcean API.** It implements the two endpoints lego's
  provider calls (create and delete a domain record) and writes into the
  DNS server. lego is pointed at it with `DO_API_URL`.
- **Trusting Pebble.** `LEGO_CA_CERTIFICATES` points lego at Pebble's
  test root (`test/certs/pebble.minica.pem` in the Pebble module).
- **Test hook.** `issuer.ExtraDNSOptions` disables lego's check against
  the zone's authoritative nameservers, which always queries port 53.
  Production code doesn't use it.

What it checks:

- a certificate for `svc.partner.test` plus `*.svc.partner.test` is issued
  through the delegation;
- every TXT write lands on the delegate label (two writes, one per
  authorization), and all of them are removed afterwards;
- a hostname with no CNAME is refused by the delegation guard;
- a second cycle uses ARI scheduling and doesn't reissue;
- `renew -force` produces a new version.

---

## 3. Distribution in containers

```
tests/compose/run.sh                      # KEEP=1 leaves containers up
```

This builds the production image from `Containerfile` and pushes to two
test nodes configured exactly as the README's
[node-side contract](../README.md#node-side-contract) describes.
Certificates are **imported** (`acme-steward import`), so no CA is needed.

### Topology

```
 network 172.30.99.0/24 (SUBNET_PREFIX overrides 172.30.99)

 steward   .10   acme-steward:test (from Containerfile), entrypoint "sleep infinity";
                 the test runs commands in it with `docker compose exec`
 intruder  .20   same image, same key and config, but a different address
 node1     .11   sshd + certdeploy account
 node2     .12   sshd + certdeploy account; a member of both clusters
```

Configuration under test:

```yaml
clusters:
  - {name: c1, remote_dir: ., nodes: [{host: node1}, {host: node2}]}
  - {name: c2, remote_dir: ., nodes: [{host: node2}]}
certificates:
  - {name: alpha, ..., clusters: [c1]}
  - {name: beta,  ..., clusters: [c2]}
```

### Plumbing

`run.sh` creates a temporary `$WORK` directory and generates the following
into it. Nothing secret is committed.

- **Steward SSH key** (`steward/ssh_key`, mode 0644). The container runs
  as uid 10001 and the file belongs to the host user. ssh only rejects a
  world-readable key when the *current* user owns it, so 0644 is accepted.
  Production should use a root-owned, group-readable secret mount instead
  (see README).
- **Node host keys** (`nodeN/ssh_host_ed25519_key`) and a `known_hosts`
  file listing them by service name, so host-key checking is strict and
  real.
- **`authorized_keys`** for each node:

  ```
  from="172.30.99.10",restrict,command="rrsync -wo /srv/certs" ssh-ed25519 ...
  ```

  The steward needs a fixed IP for this, hence the static addresses on the
  compose network.
- **Test certificates** made with `openssl`, from a throwaway CA.

The node image (`tests/compose/node/`) is Debian with `openssh-server`,
`rsync` and `python3`. Debian's `/usr/bin/rrsync` is a Python script. Its
entrypoint copies the mounted keys into place with the ownership and modes
sshd requires, then runs `sshd -D -e`, so sshd's log goes to `docker
compose logs`. The healthcheck waits for `/run/sshd.pid`, which lets
`compose up --wait` block until the nodes are ready.

`check-contract ROOT NAME [--version V] [--max-versions N]` runs inside a
node and checks the delivered tree:

- `current` is a sibling symlink, and the manifest's name and version match it;
- every file's sha256 matches the manifest;
- `fullchain.pem` starts with `cert.pem`;
- `privkey.pem` is not group or world readable;
- everything is owned by `certdeploy`;
- there are no leftover temporary files, and no more than N versions.

### Test cases

| # | Case | How |
|---|---|---|
| 1 | Each certificate reaches only its clusters and meets the contract | `alpha` lands on node1 and node2; `beta` on node2 only |
| 2 | A repeat push is a no-op | the log shows `push.node_current` events and no `push.node_updated` |
| 3 | The key can't run commands | `ssh certdeploy@node1 id` is refused by rrsync |
| 4 | `from=` is enforced | the intruder's push fails with `Permission denied (publickey)` |
| 5 | Host keys are verified | the `known_hosts` entry is renamed, and the push fails host-key verification |
| 6 | A down node doesn't block others | `compose stop node2`, import a new version, push: exit 1, node1 updated, `status` shows node2 `stale` |
| 7 | A node catches up | `compose start node2`, push: node2 is current |
| 8 | Pruning reaches the nodes | three more versions: at most 3 remain on each node, the oldest is gone, `beta` is untouched |

### Lessons learned

- **rrsync allows only one session per directory.** The first run of
  this test found that a node in two clusters received two simultaneous
  pushes, and rrsync rejected the second ("Another instance of rrsync is
  already accessing this directory"). Pushes are now grouped per host and
  run one at a time. Unit tests with a fake ssh could not have found this.
- **`COPY` keeps the file mode** from the build context. Use
  `COPY --chmod=0755` for scripts.
- A negative test must fail for the *intended* reason. The first intruder
  test "passed" because the intruder had nothing to push. It now imports a
  certificate first and asserts the specific `Permission denied
  (publickey)` error.

---

## 4. Live test: Let's Encrypt staging + DigitalOcean

```
E2E_DO_PARTNER_TOKEN=... E2E_DO_PARTNER_ZONE=acme-partner-test.fyi \
E2E_DO_PROVIDER_TOKEN=... E2E_DO_PROVIDER_ZONE=acme-delegate-test.fyi \
  tests/live/run.sh                      # KEEP=1 leaves containers up
```

> **Status:** implemented (`tests/live/`, `.github/workflows/live.yml`),
> but not yet run against the real accounts.

This test reuses the distribution topology from §3 (via
`tests/compose/lib.sh`), with nothing faked on the issuance side:

- the CA is **Let's Encrypt staging**, which validates from several network
  locations and checks CAA;
- DNS is **real DigitalOcean zones**, resolved through public resolvers;
- the challenge record is reached through a **real partner CNAME**.

It needs `docker`, `jq`, `curl`, `dig` and `ssh-keygen`; GitHub's
`ubuntu-latest` has them all. A run takes a few minutes, mostly waiting
for DNS propagation and validation.

### Accounts and zones (set up once, manually)

Two DigitalOcean accounts, mirroring the production split of control:

| Account | Zone | Plays | Token held by |
|---|---|---|---|
| partner | `acme-partner-test.fyi` | a partner's production zone | the test harness only |
| provider | `acme-delegate-test.fyi` | the steward's delegate zone | the steward container only |

Requirements:

- Both domains are registered and delegated to DigitalOcean
  (`ns1`–`ns3.digitalocean.com`).
- Each token has write access to domains in its own account.
- The partner zone has a baseline CAA record (see [CAA](#caa)):
  ```
  acme-partner-test.fyi.  CAA  0 issue "letsencrypt.org"
  ```
- Nothing is pre-created in the provider zone.

GitHub `e2e` environment:

| Kind | Name |
|---|---|
| secret | `E2E_DO_PARTNER_TOKEN` |
| secret | `E2E_DO_PROVIDER_TOKEN` |
| variable | `E2E_DO_PARTNER_ZONE` |
| variable | `E2E_DO_PROVIDER_ZONE` |

The workflows skip themselves until `E2E_DO_PARTNER_ZONE` is set.

### What each run creates

Runs create **records** inside the two existing zones. No sub-zones or NS
delegations are created. Each run picks a prefix `RUN` = `r<GitHub run
ID>-<attempt>` (or `r<unix time>` locally), and uses three hostnames:

| Certificate | Hostname | Partner records the harness adds | Expected |
|---|---|---|---|
| `main` | `RUN.<zone>` and `*.RUN.<zone>` | CNAME (from `onboard`); `A 192.0.2.10` | issued (baseline zone CAA applies) |
| `otherca` | `RUN-ca.<zone>` | CNAME; `CAA 0 issue "pki.goog"` | `check` NOT READY; the CA refuses (CAA) |
| `nocname` | `RUN-none.<zone>` | none | `check` NOT READY; refused by the delegation guard without contacting the CA |

**CAA account pinning is not tested live.** DigitalOcean's DNS API rejects
any CAA value carrying RFC 8657 parameters (`accounturi`,
`validationmethods`) with "Data needs to be a FQDN with issue or
issuewild". So a DigitalOcean-hosted partner zone can't hold a pinned
record. The live test still checks that `onboard` offers the correct
pinning value for our account. How `check` evaluates pinned records is
covered by the unit tests. Testing that Let's Encrypt enforces pinning
would need a partner test zone at a provider that accepts the parameters.
The same API also requires the issuer as an FQDN with a trailing dot
(`pki.goog.`), although the value is served without it.

acme-steward itself, using only the provider token, creates and deletes the
challenge `TXT` records at each `<label>.<provider zone>`. The harness uses
the provider token only to check, afterwards, that none were left behind.

CAA is looked up at the certificate's hostname first, then towards the zone
apex, and the first CAA set found applies. That is why CAA records on
individual per-run names can override the zone's baseline for the CAA
cases.

### Avoiding negative caching

Resolvers cache "no such name" (NXDOMAIN) answers for the zone's negative
TTL, which is 30 minutes at DigitalOcean. **DigitalOcean's own
authoritative nameservers do this too.** If anything queries a name before
its new record is published, that record stays invisible, even at
DigitalOcean, until the cached answer expires. We measured this on the test
zones:

| Experiment | Result |
|---|---|
| Create a record that nothing has queried, query after 35s | served by `ns1`–`ns3` |
| Query a name, then create its record | still NXDOMAIN at `ns1`–`ns3` minutes later |
| Placeholder TXT exists; add a second TXT | visible on all three in about 38s |
| Delete it | gone in about 33s |
| Add another on the same name | visible in about 28s |

This is the same race previously seen with cert-manager creating records at
DigitalOcean. It affects acme-steward in production, not just the test:
lego queries the delegate label (following the partner's CNAME, and finding
the zone) *before* it creates the challenge record. So:

1. **acme-steward keeps a placeholder TXT record at every delegate label**
   (see README, Initial setup). The name always exists, so nothing caches
   NXDOMAIN for it, and changes to its TXT records show up within the
   record TTL.
2. **`check` and `onboard` never look up the delegate label.** The zone
   lookup starts at the hostname, because a recursive SOA lookup of the
   `_acme-challenge` name would follow the CNAME into the delegate zone.
3. **The harness never queries a per-run name before creating it.** It
   gets the CNAME targets from `acme-steward records`, which does no
   lookups, creates the partner records, waits 60 seconds, then confirms
   with `ns1`–`ns3`. Only then does it run `onboard` and `check`.
4. **Fresh names per run** mean no earlier run can have left a cached
   negative answer behind. This also avoids Let's Encrypt's
   duplicate-certificate limit and collisions between runs.

A related effect showed up on the first issuance attempt. lego's
propagation check passed within seconds, from the runner's nearest
DigitalOcean nameservers. But Let's Encrypt, validating from several
locations, still saw only the placeholder: "Incorrect TXT record
\"acme-steward placeholder: ...\" found". Some nameserver instances serve
the previous TXT set for a while (up to about 40s in our measurements). So
acme-steward waits `dns.propagation_settle` (default 90s) after the check
passes, before asking the CA to validate.

For real partners, the same caching can delay `check` seeing a new CNAME
by up to their zone's negative TTL if anything looked the name up first
(for example, an earlier `check` run). It sorts itself out; `check -wait`
covers it.

### Flow

1. Generate SSH keys and the two configs. Write the provider token to a file
   mounted into the steward (`DO_AUTH_TOKEN_FILE`), and start the steward
   and both nodes.
2. `acme-steward account` registers a staging account and prints its URI.
3. The harness, acting as the partner, gets the CNAME targets from
   `acme-steward records`, creates the records through the partner
   account's API, waits 60 seconds, then confirms that `ns1`–`ns3` serve
   them.
4. `acme-steward onboard main` runs and is printed in the log as the
   partner would now receive it. It must show the CNAME step as "ALREADY
   DONE", require nothing, say no CAA change is needed, and offer a
   pinning value naming our staging account.
5. `check -wait 15m main` must report READY. `check` for the other two
   must report NOT READY, with the expected reason.
6. `cycle`:
   - `main` is issued by a staging intermediate and delivered to both
     nodes, passing `check-contract`;
   - `otherca` fails with a CAA error from the CA;
   - `nocname` fails at the delegation guard;
   - no challenge TXT records remain in the provider zone.
7. Second `cycle`: no reissue, and the renewal schedule comes from ARI.
8. `renew -force main` then `push`: the new version reaches both nodes, and
   the previous one is retained.
9. Cleanup always runs (a `trap`): delete this run's partner records and
   any leftover provider TXT records, then tear down the containers.

### Cleanup and hygiene

- `tests/live/sweep.sh` runs daily (`live-sweep.yml`). It deletes
  partner-zone records whose names start with `r<digit>` or
  `_acme-challenge.r<digit>`, and provider-zone TXT records starting with
  `r<digit>`. It never touches the apex CAA, NS or SOA records.
- The live test and the sweep share the `live-dns` concurrency group, so
  the sweep can never delete records of a run in progress (and live runs
  never overlap each other).
- Tokens are passed to curl through header files (mode 0600), never on a
  command line, and are never printed.
- Each run registers a new staging account (the data volume is fresh),
  which is fine for staging. That is also why the zone-level CAA must not
  pin `accounturi`.

### Triggers

Pushes to main, a weekly schedule, and manual dispatch, in the GitHub `e2e`
environment. Pull requests from forks don't receive secrets, so tiers 1–3
remain the open check on every PR.

---

## CAA

**What it is.** A CAA record ([RFC 8659](https://www.rfc-editor.org/rfc/rfc8659))
lists which CAs may issue certificates for a name. CAs must check it
before issuing. With no CAA record, any CA may issue. The lookup starts at
the certificate's hostname and climbs towards the root, and the first name
that has a CAA set wins. CNAMEs on the hostname itself are followed.

```
example.com.  CAA  0 issue     "letsencrypt.org"     ; who may issue
example.com.  CAA  0 issuewild "letsencrypt.org"     ; who may issue wildcards (defaults to issue)
example.com.  CAA  0 iodef     "mailto:sec@example.com"
```

[RFC 8657](https://www.rfc-editor.org/rfc/rfc8657) adds two parameters to
`issue`/`issuewild`:

- `accounturi=<ACME account URL>` allows only that ACME account to obtain
  certificates;
- `validationmethods=dns-01` allows only those challenge types.

**Which name's CAA matters here.** The CA checks CAA for the *partner's
hostname* (e.g. `sync.partner.com`, then `partner.com`). The delegate zone
is not checked: only `_acme-challenge` is CNAMEd there, not the hostname.
So CAA is entirely the partner's decision. A CAA record in our delegate
zone has no effect on partner certificates.

**What it means for partners.**

- If their zone has no CAA, nothing is needed.
- If it has CAA, it must allow `letsencrypt.org`. Otherwise issuance fails.
  `acme-steward check` detects this and prints the record to add.
- **Recommended hardening.** Pin issuance to our ACME account:

  ```
  sync.partner.com.  CAA  0 issue "letsencrypt.org; accounturi=<our account URI>; validationmethods=dns-01"
  ```

  This is the main mitigation for the delegation's biggest risk. Anyone
  holding our DigitalOcean token can answer DNS-01 challenges for every
  delegated name, but with `accounturi` pinned they would also need our
  ACME account key. The cost is that losing that key, or moving to
  another CA or account, requires every pinning partner to update their
  record. Hence the README's advice to back up the account key.
- `acme-steward check` fails if a partner's CAA pins a different account,
  or restricts `validationmethods` in a way that excludes `dns-01`.
- **Not every DNS provider can pin.** DigitalOcean's DNS rejects CAA values
  with parameters, and other providers may too. `onboard`'s optional
  pinning step tells partners to skip it if their provider rejects the
  value. With `caa_pin: required`, such partners can't comply, so use it
  only for partners known to be able to.

**For the CI zones.** Put the baseline `0 issue "letsencrypt.org"` on the
partner test zone. It makes the zone look like a realistic, CAA-using
partner, and exercises the CAA "OK" path against real DNS on every run.
Don't pin `accounturi` at the zone level: each run registers a new staging
account. Pinning and refusal are tested on per-run names (above). The
provider test zone needs no CAA.

---

## Reusing this pattern elsewhere

- **Stack the tiers.** Each tier replaces one fake with the real thing.
  Unit tests check logic, the local CA checks protocol behaviour, the
  containers check transport and permissions, and the live tier checks
  third-party behaviour. Only the last needs secrets, so forks still get
  meaningful CI.
- **Make the "remote host" a container built to the documented contract.**
  Use the exact `authorized_keys` line from the README, give the client a
  fixed IP for `from=`, add a contract checker on the target side, and run
  a negative twin (the intruder) that differs in exactly one property.
- **Generate every credential per run** (client key, host keys,
  `known_hosts`), so strict host-key checking stays on in tests.
- **Use fresh DNS names per run** against real zones, create records
  before anything queries them, clean up in a trap, and back that up with
  a scheduled sweep.
- **Split credentials the way production does** (the partner token stays
  with the harness, the provider token with the system under test), so
  the test also proves isolation.
