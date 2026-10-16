package steward

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/store"
	"github.com/bozemanpass/acme-steward/internal/testutil"
)

type fakeIssuer struct {
	now      func() time.Time
	lifetime time.Duration
	obtains  int
	replaced int
	err      error
	ri       *RenewalInfo
	riErr    error
}

func (f *fakeIssuer) Obtain(ct *config.Certificate, replacing *x509.Certificate) (*store.Bundle, error) {
	f.obtains++
	if f.err != nil {
		return nil, f.err
	}
	if replacing != nil {
		f.replaced++
	}
	now := f.now()
	cert, key, chain := testutil.Cert(ct.Domains, now, now.Add(f.lifetime))
	return &store.Bundle{Name: ct.Name, Domains: ct.Domains, KeyType: ct.KeyType, Key: key, Cert: cert, Chain: chain}, nil
}

func (f *fakeIssuer) RenewalInfo(*x509.Certificate) (*RenewalInfo, error) { return f.ri, f.riErr }
func (f *fakeIssuer) AccountURI() string                                  { return "https://ca/acct/1" }

type env struct {
	s     *Steward
	iss   *fakeIssuer
	now   time.Time
	logs  *bytes.Buffer
	nodes map[string]string // host -> remote dir
	fail  string            // touch to make pushes fail
}

func newEnv(t *testing.T) *env {
	t.Helper()
	remote1, remote2 := t.TempDir(), t.TempDir()
	cfg, err := config.Parse([]byte(`
acme: {ca: letsencrypt-staging}
dns: {delegate_zone: d.example.net}
ssh: {user: u, key_file: /k, known_hosts_file: /kh}
clusters:
  - name: c1
    remote_dir: ` + remote1 + `
    nodes: [{host: n1}]
  - name: c2
    remote_dir: ` + remote2 + `
    nodes: [{host: n2}]
certificates:
  - {name: a, domains: [a.example.com], clusters: [c1, c2]}
  - {name: b, domains: [b.example.com], clusters: [c2]}
`))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), logs: &bytes.Buffer{},
		nodes: map[string]string{"n1": remote1, "n2": remote2}, fail: filepath.Join(t.TempDir(), "fail")}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.s = New(cfg, st, log, "")
	e.s.Now = func() time.Time { return e.now }
	e.iss = &fakeIssuer{now: e.s.Now, lifetime: 90 * 24 * time.Hour}
	e.s.NewIssuer = func() (Issuer, error) { return e.iss, nil }
	e.s.Pusher.SSHCommand = testutil.FakeSSH(t, e.fail)
	return e
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

func TestRenewalSchedule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	e.s.RenewAll(ctx, nil, false)
	if e.iss.obtains != 2 {
		t.Fatal("initial issuance", e.iss.obtains)
	}
	// Not due: fallback renews at 2/3 of 90 days = day 60.
	e.advance(59 * 24 * time.Hour)
	e.s.RenewAll(ctx, nil, false)
	if e.iss.obtains != 2 {
		t.Fatal("renewed too early")
	}
	// ARI state is cached; after ARINextCheck passes it is re-read.
	e.advance(2 * 24 * time.Hour)
	e.s.RenewAll(ctx, nil, false)
	if e.iss.obtains != 4 || e.iss.replaced != 2 {
		t.Fatal("lifetime-based renewal", e.iss.obtains, e.iss.replaced)
	}
	st, _ := e.s.Store.CertState("a")
	if len(st.Issued) != 1 { // history only covers the last week
		t.Error("issued history", st.Issued)
	}
}

func TestARIWindow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.s.RenewAll(ctx, []string{"a"}, false)
	// CA asks for early renewal (e.g. mass revocation).
	e.iss.ri = &RenewalInfo{Start: e.now.Add(-time.Hour), End: e.now.Add(-time.Minute)}
	e.advance(7 * time.Hour) // past the default 6h ARI recheck
	e.s.RenewAll(ctx, []string{"a"}, false)
	if e.iss.obtains != 2 {
		t.Fatal("ARI-triggered renewal did not happen", e.iss.obtains)
	}
	if !strings.Contains(e.logs.String(), "reason=scheduled_ari") {
		t.Error("expected ari reason in logs")
	}
}

func TestBackoffAndGuard(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.iss.err = errors.New("acme: error: 400 :: urn:ietf:params:acme:error:dns")
	e.s.RenewAll(ctx, []string{"a"}, false)
	e.advance(30 * time.Minute)
	e.s.RenewAll(ctx, []string{"a"}, false)
	if e.iss.obtains != 1 {
		t.Fatal("did not back off", e.iss.obtains)
	}
	e.advance(31 * time.Minute) // past retry_min (1h)
	e.s.RenewAll(ctx, []string{"a"}, false)
	if e.iss.obtains != 2 {
		t.Fatal("did not retry after backoff", e.iss.obtains)
	}
	st, _ := e.s.Store.CertState("a")
	if st.Failures != 2 || !st.NextAttempt.Equal(e.now.Add(2*time.Hour)) {
		t.Error("exponential backoff", st.Failures, st.NextAttempt)
	}

	// Issuance guard: a domain change each time would loop forever.
	e.iss.err = nil
	e.advance(3 * time.Hour)
	ct := e.s.Cfg.Cert("a")
	for i := range 5 {
		ct.Domains = []string{"a.example.com", "x" + string(rune('0'+i)) + ".example.com"}
		e.s.RenewAll(ctx, []string{"a"}, false)
	}
	if e.iss.obtains != 2+3 {
		t.Error("guard should cap at 3 per week", e.iss.obtains)
	}
	if !strings.Contains(e.logs.String(), "event=cert.rate_guard") {
		t.Error("guard not logged")
	}
	e.s.RenewAll(ctx, []string{"a"}, true)
	if e.iss.obtains != 6 {
		t.Error("force should bypass guard")
	}
}

func TestPushAndExpiry(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed")
	}
	e := newEnv(t)
	ctx := context.Background()
	e.s.Cycle(ctx)
	for host, dir := range e.nodes {
		if _, err := os.Stat(filepath.Join(dir, "a", "current", store.FileFullchain)); err != nil {
			t.Errorf("%s: cert a not delivered: %v", host, err)
		}
	}
	if _, err := os.Stat(filepath.Join(e.nodes["n1"], "b")); !os.IsNotExist(err) {
		t.Error("cert b pushed to a cluster it is not configured for")
	}
	ps, _ := e.s.Store.PushState()
	cur, _ := e.s.Store.Current("a")
	if ps["c2/n2"]["a"].Version != cur.Version {
		t.Error("push state", ps)
	}
	if err := e.s.Healthy(); err != nil {
		t.Error(err)
	}

	// Node unreachable: failure recorded, version left as last delivered.
	os.WriteFile(e.fail, nil, 0o600)
	e.s.Cycle(ctx)
	ps, _ = e.s.Store.PushState()
	if np := ps["c1/n1"]["a"]; np.Failures != 1 || np.Version != cur.Version {
		t.Error("failure state", np)
	}
	if !strings.Contains(e.logs.String(), "event=push.node_failed") {
		t.Error("failure not logged")
	}

	// Renewal keeps failing; expiry warnings appear in the last 1/6.
	e.iss.err = errors.New("boom")
	e.advance(80 * 24 * time.Hour)
	e.s.CheckExpiry()
	if !strings.Contains(e.logs.String(), "event=cert.expiry_warning") {
		t.Error("no expiry warning")
	}
	e.advance(11 * 24 * time.Hour)
	e.s.CheckExpiry()
	if !strings.Contains(e.logs.String(), "event=cert.expired") {
		t.Error("no expired error")
	}
	if e.s.Healthy() == nil {
		t.Error("stale heartbeat should be unhealthy")
	}
}

func TestDelegateLabelOverride(t *testing.T) {
	ct := &config.Certificate{DelegateLabels: map[string]string{"x.example.com": "custom"}}
	if DelegateLabel(ct, "*.x.example.com") != "custom" {
		t.Error("override not used")
	}
	if DelegateLabel(ct, "y.example.com") == "custom" {
		t.Error("override applied to wrong domain")
	}
}

func TestImport(t *testing.T) {
	e := newEnv(t)
	cert, key, chain := testutil.Cert([]string{"a.example.com"}, e.now, e.now.Add(90*24*time.Hour))
	if _, err := e.s.Import(e.s.Cfg.Cert("a"), cert, key, nil); err != nil {
		t.Fatal(err)
	}
	m, _ := e.s.Store.Current("a")
	if m.KeyType != "ec256" || m.Domains[0] != "a.example.com" {
		t.Errorf("manifest %+v", m)
	}
	// Matches config, not due: no issuance.
	e.s.RenewAll(context.Background(), []string{"a"}, false)
	if e.iss.obtains != 0 {
		t.Error("imported certificate was replaced immediately")
	}
	_, otherKey, _ := testutil.Cert([]string{"x"}, e.now, e.now.Add(time.Hour))
	if _, err := e.s.Import(e.s.Cfg.Cert("a"), cert, otherKey, chain); err == nil {
		t.Error("mismatched key accepted")
	}
}

// A host in several clusters gets one push per remote directory, never two
// at once.
func TestPushSharedHost(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed")
	}
	e := newEnv(t)
	// Put n1 in both clusters, with c2's remote dir.
	e.s.Cfg.Clusters[0].Nodes = append(e.s.Cfg.Clusters[0].Nodes, config.Node{Host: "n2", User: "u", Port: 22})
	e.s.Cfg.Clusters[0].RemoteDir = e.s.Cfg.Clusters[1].RemoteDir
	// Fake ssh that fails if another session for the same host is active.
	lockDir := t.TempDir()
	script := filepath.Join(t.TempDir(), "lockssh")
	os.WriteFile(script, []byte(`#!/bin/sh
while [ "$1" != "rsync" ]; do host=$1; shift; done
mkdir "`+lockDir+`/$host" 2>/dev/null || { echo "concurrent session" >&2; exit 12; }
"$@"; rc=$?
rmdir "`+lockDir+`/$host"
exit $rc
`), 0o755)
	e.s.Pusher.SSHCommand = script
	e.s.RenewAll(context.Background(), nil, false)
	for range 5 {
		if f := e.s.PushAll(context.Background(), nil); f != 0 {
			t.Fatalf("%d push failures:\n%s", f, e.logs.String())
		}
	}
	if n := strings.Count(e.logs.String(), "event=push.node_updated"); n != 2 {
		t.Errorf("expected 2 updates (n1, merged n2), got %d\n%s", n, e.logs.String())
	}
	ps, _ := e.s.Store.PushState()
	if ps["c1/n2"]["a"].Version == "" || ps["c2/n2"]["b"].Version == "" {
		t.Errorf("state for both clusters not recorded: %+v", ps)
	}
}
