// Package dnscheck verifies a partner's DNS is ready for delegated DNS-01
// issuance: the _acme-challenge CNAME points at our delegate label (as seen
// by public resolvers and by the partner's authoritative servers), CAA
// permits our CA, and optionally that the hostname points at the cluster.
package dnscheck

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Finding struct {
	Domain string `json:"domain"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

type Checker struct {
	Resolvers      []string // host:port, recursive
	CAAIdentifiers []string
	AccountURI     string // if set, CAA accounturi parameters are checked against it
	AuthPort       string // port for authoritative queries (tests)
	Timeout        time.Duration
}

// Target is what to check for one domain.
type Target struct {
	Domain    string   // may be a wildcard
	CNAME     string   // expected FQDN of the delegate label, no trailing dot
	Addresses []string // expected A/AAAA values; empty skips the check
}

func (c *Checker) Check(t Target) []Finding {
	c.defaults()
	wildcard := strings.HasPrefix(t.Domain, "*.")
	base := strings.TrimPrefix(t.Domain, "*.")

	var out []Finding
	add := func(check string, s Status, format string, a ...any) {
		out = append(out, Finding{Domain: t.Domain, Check: check, Status: s, Detail: fmt.Sprintf(format, a...)})
	}

	ci := c.Challenge(t.Domain, t.CNAME)
	// 1. CNAME as seen by public recursive resolvers (what the CA and lego see).
	for _, r := range c.Resolvers {
		got, err := ci.Public[r], ci.PublicErr[r]
		switch {
		case err != nil:
			add("cname@"+r, Fail, "query %s: %v", ci.Name, err)
		case got == "":
			add("cname@"+r, Fail, "no CNAME at %s; partner must add: %s. CNAME %s", ci.Name, ci.Name, ci.Want)
		case got != ci.Want:
			add("cname@"+r, Fail, "%s CNAME %s, expected %s", ci.Name, got, ci.Want)
		default:
			add("cname@"+r, OK, "%s CNAME %s", ci.Name, got)
		}
	}
	// 2. CNAME at each of the partner's authoritative servers, so a
	// partially propagated or split-horizon change is caught.
	for _, k := range sortedKeys(ci.AuthErr) {
		add("cname@"+k, Warn, "no answer: %v", ci.AuthErr[k])
	}
	for _, ns := range sortedKeys(ci.Auth) {
		if got := ci.Auth[ns]; got != ci.Want {
			add("cname@"+ns, Fail, "authoritative answer %q, expected %s", got, ci.Want)
		} else {
			add("cname@"+ns, OK, "%s CNAME %s", ci.Name, got)
		}
	}
	if len(ci.ExistingTXT) > 0 {
		add("conflict", Fail, "%s has TXT records %q which must be deleted before the CNAME can be added", ci.Name, ci.ExistingTXT)
	}

	// 3. CAA.
	caa := c.CAA(t.Domain)
	switch {
	case caa.Problem == CAALookupFailure:
		add("caa", Warn, "%s", caa.Detail)
	case caa.Permitted():
		add("caa", OK, "%s", caa.Detail)
	default:
		add("caa", Fail, "%s", caa.Detail)
	}

	// 4. A/AAAA point at the cluster (informational).
	if len(t.Addresses) > 0 && !wildcard {
		hi := c.Host(base)
		var stray []string
		for _, a := range hi.Addrs {
			if !slices.Contains(t.Addresses, a) {
				stray = append(stray, a)
			}
		}
		switch {
		case len(hi.Addrs) == 0:
			add("address", Warn, "%s has no A/AAAA records", base)
		case len(stray) > 0:
			add("address", Warn, "%s resolves to %v, not in cluster addresses %v", base, stray, t.Addresses)
		default:
			add("address", OK, "%s resolves to %v", base, hi.Addrs)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func parseCAAValue(v string) (issuer string, params map[string]string) {
	parts := strings.Split(v, ";")
	issuer = strings.ToLower(strings.TrimSpace(parts[0]))
	params = map[string]string{}
	for _, p := range parts[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
		params[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
	}
	return issuer, params
}

type server struct {
	name  string
	addrs []string // IPv4 first
}

// cnameAny asks each address in turn until one answers.
func (c *Checker) cnameAny(name string, addrs []string) (string, error) {
	var err error
	for _, a := range addrs {
		var got string
		if got, err = c.cname(name, a, false); err == nil {
			return got, nil
		}
	}
	return "", err
}

// zoneServers resolves the NS hosts of zone.
func (c *Checker) zoneServers(zone string) ([]server, error) {
	rrs, err := c.query(zone, dns.TypeNS, c.Resolvers[0], true)
	if err != nil {
		return nil, err
	}
	var out []server
	for _, rr := range rrs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		host := strings.TrimSuffix(ns.Ns, ".")
		srv := server{name: host}
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			as, err := c.query(host, qt, c.Resolvers[0], true)
			if err != nil {
				continue
			}
			for _, a := range as {
				switch v := a.(type) {
				case *dns.A:
					srv.addrs = append(srv.addrs, net.JoinHostPort(v.A.String(), c.AuthPort))
				case *dns.AAAA:
					srv.addrs = append(srv.addrs, net.JoinHostPort(v.AAAA.String(), c.AuthPort))
				}
			}
		}
		if len(srv.addrs) > 0 {
			out = append(out, srv)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no addresses for nameservers of %s", zone)
	}
	return out, nil
}

// findZone returns the closest enclosing zone cut (name with an SOA) for name.
func (c *Checker) findZone(name string) (string, error) {
	labels := dns.SplitDomainName(name)
	for i := range labels {
		cand := strings.Join(labels[i:], ".")
		m, err := c.exchange(cand, dns.TypeSOA, c.Resolvers[0], true)
		if err != nil {
			return "", err
		}
		for _, rr := range m.Answer {
			if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(cand)) {
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("no SOA found above %s", name)
}

// cname returns the lowercase FQDN target of the CNAME at name, or "".
func (c *Checker) cname(name, server string, recurse bool) (string, error) {
	m, err := c.exchange(name, dns.TypeCNAME, server, recurse)
	if err != nil {
		return "", err
	}
	for _, rr := range m.Answer {
		if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cn.Hdr.Name, dns.Fqdn(name)) {
			return strings.ToLower(cn.Target), nil
		}
	}
	return "", nil
}

func (c *Checker) query(name string, qtype uint16, server string, recurse bool) ([]dns.RR, error) {
	m, err := c.exchange(name, qtype, server, recurse)
	if err != nil {
		return nil, err
	}
	return m.Answer, nil
}

func (c *Checker) exchange(name string, qtype uint16, server string, recurse bool) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = recurse
	q.SetEdns0(1232, false)
	cl := &dns.Client{Timeout: c.Timeout}
	m, _, err := cl.Exchange(q, server)
	if err == nil && m.Truncated {
		cl.Net = "tcp"
		m, _, err = cl.Exchange(q, server)
	}
	if err != nil {
		return nil, err
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%s", dns.RcodeToString[m.Rcode])
	}
	return m, nil
}
