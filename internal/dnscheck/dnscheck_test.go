package dnscheck

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeDNS serves a fixed set of records, acting as both the recursive
// resolver and the authoritative server.
func fakeDNS(t *testing.T, records []string) (addr, port string) {
	t.Helper()
	byKey := map[string][]dns.RR{}
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatal(r, err)
		}
		k := strings.ToLower(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		byKey[k] = append(byKey[k], rr)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := strings.ToLower(q.Question[0].Name)
		qt := dns.TypeToString[q.Question[0].Qtype]
		m.Answer = byKey[name+"/"+qt]
		if len(m.Answer) == 0 && qt != "CNAME" {
			m.Answer = byKey[name+"/CNAME"] // like a resolver would show the alias
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	_, port, _ = net.SplitHostPort(pc.LocalAddr().String())
	return pc.LocalAddr().String(), port
}

func statuses(fs []Finding) map[string]Status {
	out := map[string]Status{}
	for _, f := range fs {
		out[f.Check] = f.Status
	}
	return out
}

func TestCheck(t *testing.T) {
	addr, port := fakeDNS(t, []string{
		"partner.test. 60 IN SOA ns1.partner.test. h.partner.test. 1 2 3 4 5",
		"partner.test. 60 IN NS ns1.partner.test.",
		"ns1.partner.test. 60 IN A 127.0.0.1",
		"_acme-challenge.good.partner.test. 60 IN CNAME good-x.d.example.net.",
		"_acme-challenge.bad.partner.test. 60 IN CNAME elsewhere.example.org.",
		"good.partner.test. 60 IN A 203.0.113.10",
		`partner.test. 60 IN CAA 0 issue "letsencrypt.org; accounturi=https://ca/acct/1"`,
		`other.test. 60 IN SOA ns1.partner.test. h.partner.test. 1 2 3 4 5`,
		`other.test. 60 IN NS ns1.partner.test.`,
		`other.test. 60 IN CAA 0 issue "pki.goog"`,
		`other.test. 60 IN CAA 0 issuewild "letsencrypt.org"`,
		"_acme-challenge.w.other.test. 60 IN CNAME w-x.d.example.net.",
		`vm.test. 60 IN SOA ns1.partner.test. h.partner.test. 1 2 3 4 5`,
		`http.vm.test. 60 IN CAA 0 issue "letsencrypt.org; validationmethods=http-01"`,
		`dns.vm.test. 60 IN CAA 0 issue "letsencrypt.org; validationmethods=http-01,dns-01"`,
		`two.vm.test. 60 IN CAA 0 issue "letsencrypt.org; accounturi=https://ca/acct/old"`,
		`two.vm.test. 60 IN CAA 0 issue "letsencrypt.org; accounturi=https://ca/acct/1"`,
		"_acme-challenge.stale.partner.test. 60 IN TXT \"old-token\"",
	})
	c := &Checker{Resolvers: []string{addr}, CAAIdentifiers: []string{"letsencrypt.org"},
		AccountURI: "https://ca/acct/1", AuthPort: port}

	good := statuses(c.Check(Target{Domain: "good.partner.test", CNAME: "good-x.d.example.net", Addresses: []string{"203.0.113.10"}}))
	want := map[string]Status{"cname@" + addr: OK, "cname@ns1.partner.test": OK, "caa": OK, "address": OK}
	for k, v := range want {
		if good[k] != v {
			t.Errorf("good %s = %q, want %q (%v)", k, good[k], v, good)
		}
	}

	bad := statuses(c.Check(Target{Domain: "bad.partner.test", CNAME: "bad-x.d.example.net", Addresses: []string{"203.0.113.10"}}))
	if bad["cname@"+addr] != Fail || bad["cname@ns1.partner.test"] != Fail || bad["address"] != Warn {
		t.Errorf("bad: %v", bad)
	}

	missing := statuses(c.Check(Target{Domain: "none.partner.test", CNAME: "n.d.example.net"}))
	if missing["cname@"+addr] != Fail {
		t.Errorf("missing: %v", missing)
	}

	// accounturi pinned to a different account.
	c2 := *c
	c2.AccountURI = "https://ca/acct/2"
	if st := statuses(c2.Check(Target{Domain: "good.partner.test", CNAME: "good-x.d.example.net"})); st["caa"] != Fail {
		t.Errorf("accounturi mismatch not detected: %v", st)
	}

	// issue forbids us but issuewild permits: depends on wildcard.
	if st := statuses(c.Check(Target{Domain: "*.w.other.test", CNAME: "w-x.d.example.net"})); st["caa"] != OK {
		t.Errorf("wildcard CAA: %v", st)
	}
	if st := statuses(c.Check(Target{Domain: "w.other.test", CNAME: "w-x.d.example.net"})); st["caa"] != Fail {
		t.Errorf("non-wildcard CAA: %v", st)
	}

	// Any one record permitting us is enough.
	if info := c.CAA("two.vm.test"); !info.Permitted() || !info.PinnedToUs || info.Owner != "two.vm.test" {
		t.Errorf("second record should permit: %+v", info)
	}
	if info := c.CAA("none.partner.test"); !info.Permitted() || !info.PinnedToUs || info.Owner != "partner.test" {
		t.Errorf("inherited CAA: %+v", info)
	}

	// Left-over TXT records block the CNAME.
	ci := c.Challenge("stale.partner.test", "s.d.example.net")
	if ci.Zone != "partner.test" || len(ci.ExistingTXT) != 1 || ci.Delegated() {
		t.Errorf("stale challenge: %+v", ci)
	}
	if !c.Challenge("good.partner.test", "good-x.d.example.net").Delegated() {
		t.Error("good delegation not recognised")
	}

	// validationmethods must allow dns-01.
	if st := statuses(c.Check(Target{Domain: "http.vm.test", CNAME: "x.d.example.net"})); st["caa"] != Fail {
		t.Errorf("validationmethods=http-01 not rejected: %v", st)
	}
	if st := statuses(c.Check(Target{Domain: "dns.vm.test", CNAME: "x.d.example.net"})); st["caa"] != OK {
		t.Errorf("validationmethods including dns-01 rejected: %v", st)
	}
}
