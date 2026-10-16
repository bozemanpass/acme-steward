//go:build e2e

// End-to-end test against Pebble (a test ACME CA), a fake DigitalOcean API
// and an in-process DNS server holding the partner and delegate zones.
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
//	go test -tags e2e ./internal/e2e
//
// PEBBLE_BIN may point at the binary; PEBBLE_DIR at the pebble module
// source (for its test certificates), defaulting to the module cache.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/dodns"
	"github.com/bozemanpass/acme-steward/internal/issuer"
	"github.com/bozemanpass/acme-steward/internal/label"
	"github.com/bozemanpass/acme-steward/internal/steward"
	"github.com/bozemanpass/acme-steward/internal/store"
	"github.com/bozemanpass/acme-steward/internal/testutil"
)

const delegateZone = "delegate.test"

// zoneDNS is a tiny DNS server that answers like a recursive resolver
// (following CNAMEs within its data) and serves SOA/NS for its zones.
type zoneDNS struct {
	mu    sync.Mutex
	zones []string
	cname map[string]string
	txt   map[string][]string
}

func (z *zoneDNS) serve(w dns.ResponseWriter, q *dns.Msg) {
	z.mu.Lock()
	defer z.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(q)
	name := strings.ToLower(q.Question[0].Name)
	qt := q.Question[0].Qtype
	hdr := func(n string, t uint16) dns.RR_Header {
		return dns.RR_Header{Name: n, Rrtype: t, Class: dns.ClassINET, Ttl: 1}
	}
	for _, zn := range z.zones {
		if name == dns.Fqdn(zn) {
			switch qt {
			case dns.TypeSOA:
				m.Answer = append(m.Answer, &dns.SOA{Hdr: hdr(name, qt), Ns: "ns." + name, Mbox: "h." + name, Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 1})
			case dns.TypeNS:
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(name, qt), Ns: "ns." + name})
			}
		}
	}
	if t, ok := z.cname[name]; ok {
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(name, dns.TypeCNAME), Target: t})
		if qt != dns.TypeCNAME {
			name = t
		}
	}
	if qt == dns.TypeTXT {
		for _, v := range z.txt[name] {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(name, qt), Txt: []string{v}})
		}
	}
	w.WriteMsg(m)
}

func (z *zoneDNS) start(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: dns.HandlerFunc(z.serve)}, {Listener: l, Handler: dns.HandlerFunc(z.serve)}} {
		go srv.ActivateAndServe()
		t.Cleanup(func() { srv.Shutdown() })
	}
	return pc.LocalAddr().String()
}

// fakeDO implements the two DigitalOcean endpoints lego uses.
func fakeDO(t *testing.T, z *zoneDNS, writes *[]string) *httptest.Server {
	var mu sync.Mutex
	ids := map[int]string{}
	data := map[int]string{}
	next := 1
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // v2 domains <zone> records [id]
		if len(parts) < 4 || parts[1] != "domains" || parts[2] != delegateZone {
			http.Error(w, "unexpected zone "+r.URL.Path, http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet: // list, filtered by type and FQDN as the real API does
			name := r.URL.Query().Get("name")
			var recs []map[string]any
			for id, n := range ids {
				if n == dns.Fqdn(name) {
					recs = append(recs, map[string]any{"id": id, "type": "TXT", "name": strings.TrimSuffix(name, "."+delegateZone), "data": data[id]})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"domain_records": recs})
		case http.MethodPost:
			var rec struct{ Type, Name, Data string }
			json.NewDecoder(r.Body).Decode(&rec)
			name := dns.Fqdn(strings.ToLower(rec.Name))
			if !strings.HasSuffix(name, "."+delegateZone+".") {
				name = dns.Fqdn(name + "." + delegateZone)
			}
			z.mu.Lock()
			z.txt[name] = append(z.txt[name], rec.Data)
			z.mu.Unlock()
			*writes = append(*writes, name)
			ids[next] = name
			data[next] = rec.Data
			fmt.Fprintf(w, `{"domain_record":{"id":%d,"type":"TXT","name":%q,"data":%q}}`, next, rec.Name, rec.Data)
			next++
		case http.MethodDelete:
			var id int
			fmt.Sscan(parts[4], &id)
			z.mu.Lock()
			z.txt[ids[id]] = slices.DeleteFunc(z.txt[ids[id]], func(v string) bool { return v == data[id] })
			if len(z.txt[ids[id]]) == 0 {
				delete(z.txt, ids[id])
			}
			z.mu.Unlock()
			delete(ids, id)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startPebble(t *testing.T, dnsAddr string) string {
	bin := os.Getenv("PEBBLE_BIN")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("pebble"); err != nil {
			t.Skip("pebble not found; set PEBBLE_BIN")
		}
	}
	dir := os.Getenv("PEBBLE_DIR")
	if dir == "" {
		out, _ := exec.Command("go", "env", "GOMODCACHE").Output()
		dir = filepath.Join(strings.TrimSpace(string(out)), "github.com/letsencrypt/pebble/v2@v2.10.1")
	}
	port := freePort(t)
	cfg := map[string]any{"pebble": map[string]any{
		"listenAddress":           fmt.Sprintf("127.0.0.1:%d", port),
		"managementListenAddress": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"certificate":             filepath.Join(dir, "test/certs/localhost/cert.pem"),
		"privateKey":              filepath.Join(dir, "test/certs/localhost/key.pem"),
		"httpPort":                freePort(t), "tlsPort": freePort(t),
		"externalAccountBindingRequired": false,
		"profiles":                       map[string]any{"default": map[string]any{"description": "d", "validityPeriod": 7776000}},
	}}
	cfgPath := filepath.Join(t.TempDir(), "pebble.json")
	b, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, b, 0o600)

	cmd := exec.Command(bin, "-config", cfgPath, "-dnsserver", dnsAddr)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log("pebble output:\n" + out.String())
		}
	})
	t.Setenv("LEGO_CA_CERTIFICATES", filepath.Join(dir, "test/certs/pebble.minica.pem"))
	for range 50 {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			return fmt.Sprintf("https://127.0.0.1:%d/dir", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("pebble did not start")
	return ""
}

func TestEndToEnd(t *testing.T) {
	z := &zoneDNS{zones: []string{delegateZone, "partner.test"}, cname: map[string]string{}, txt: map[string][]string{}}
	dnsAddr := z.start(t)
	var writes []string
	do := fakeDO(t, z, &writes)
	defer do.Close()
	t.Setenv("DO_API_URL", do.URL)
	issuer.ExtraDNSOptions = []dns01.ChallengeOption{dns01.DisableAuthoritativeNssPropagationRequirement()}
	directory := startPebble(t, dnsAddr)

	remote := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
acme: {ca: %q, accept_terms: true}
dns: {delegate_zone: %s, resolvers: [%q], propagation_timeout: 30s, propagation_settle: 0s}
ssh: {user: u, key_file: /k, known_hosts_file: /kh}
clusters:
  - {name: c, remote_dir: %q, nodes: [{host: n1}]}
certificates:
  - {name: good, domains: [svc.partner.test, "*.svc.partner.test"], clusters: [c]}
  - {name: undelegated, domains: [other.partner.test], clusters: [c]}
`, directory, delegateZone, dnsAddr, remote)))
	if err != nil {
		t.Fatal(err)
	}
	// The partner's one-time delegation, for "good" only.
	ct := cfg.Cert("good")
	target := label.Target(steward.DelegateLabel(ct, "svc.partner.test"), delegateZone)
	z.cname["_acme-challenge.svc.partner.test."] = dns.Fqdn(target)

	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	issuer.RouteLegoLogs(log.Handler())
	s := steward.New(cfg, st, log, "do-token")
	s.PlaceholderWait = 0 // the test DNS server doesn't cache
	s.Pusher.SSHCommand = testutil.FakeSSH(t, filepath.Join(t.TempDir(), "nofail"))

	s.Cycle(context.Background())
	if t.Failed() || testing.Verbose() {
		t.Log(logs.String())
	}

	m, err := st.Current("good")
	if err != nil || m == nil {
		t.Fatalf("good not issued: %v\n%s", err, logs.String())
	}
	if len(m.Domains) != 2 {
		t.Error("domains", m.Domains)
	}
	for _, w := range writes {
		if !strings.HasSuffix(w, "."+delegateZone+".") {
			t.Errorf("TXT written outside the delegate zone: %s", w)
		}
	}
	// One placeholder per label (good and undelegated), then one challenge
	// per authorization: the base name and wildcard share a label.
	if len(writes) != 4 {
		t.Errorf("expected 4 TXT writes, got %v", writes)
	}
	for n, vals := range z.txt {
		if len(vals) != 1 || vals[0] != dodns.PlaceholderValue {
			t.Errorf("challenge records not cleaned up at %s: %v", n, vals)
		}
	}
	if _, err := os.Stat(filepath.Join(remote, "good", "current", store.FileFullchain)); err != nil {
		t.Error("not pushed:", err)
	}

	if m, _ := st.Current("undelegated"); m != nil {
		t.Error("undelegated certificate was issued")
	}
	if !strings.Contains(logs.String(), "does not resolve via CNAME into delegate zone") {
		t.Error("missing delegation error not reported")
	}

	// A second cycle consults ARI and does not reissue.
	cs, _ := st.CertState("good")
	if cs.RenewAtFrom != "" {
		t.Error("unexpected schedule before second cycle", cs.RenewAtFrom)
	}
	s.Cycle(context.Background())
	cs, _ = st.CertState("good")
	if cs.RenewAtFrom != "ari" {
		t.Errorf("expected ARI-based schedule, got %q (%s)", cs.RenewAtFrom, cs.LastError)
	}
	if m2, _ := st.Current("good"); m2.Version != m.Version {
		t.Error("certificate reissued on second cycle")
	}

	// Forced renewal replaces it.
	if s.RenewAll(context.Background(), []string{"good"}, true) != 0 {
		t.Fatal("forced renewal failed:\n" + logs.String())
	}
	if m3, _ := st.Current("good"); m3.Version == m.Version {
		t.Error("forced renewal did not produce a new version")
	}
}
