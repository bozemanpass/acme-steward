package dnscheck

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CAA problems.
const (
	CAANone          = ""                   // permitted (or no CAA at all)
	CAANotPermitted  = "not_permitted"      // no record names our CA
	CAAOtherAccount  = "other_account"      // our CA pinned to a different account
	CAAMethods       = "validation_methods" // our CA limited to methods excluding dns-01
	CAANoIssuers     = "no_issuers"         // issue/issuewild set forbids every CA
	CAALookupFailure = "lookup_failed"
)

// CAAInfo describes the CAA records that govern issuance for a domain.
type CAAInfo struct {
	// Owner is where the relevant CAA set was found ("" if none exists).
	Owner string
	// Tag is the property that applies: "issue" or "issuewild".
	Tag string
	// Records are the relevant property values, e.g. `letsencrypt.org; accounturi=...`.
	Records []string
	// Problem is CAANone when issuance by our CA is permitted.
	Problem string
	// PinnedToUs is true when a record permits our CA only for our account.
	PinnedToUs bool
	Detail     string
}

func (i CAAInfo) Permitted() bool { return i.Problem == CAANone }

// CAA finds the CAA set governing domain (RFC 8659 tree climbing; a
// leading "*." means wildcard issuance) and evaluates it.
func (c *Checker) CAA(domain string) CAAInfo {
	c.defaults()
	wildcard := strings.HasPrefix(domain, "*.")
	base := strings.TrimPrefix(domain, "*.")
	labels := dns.SplitDomainName(base)
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		rrs, err := c.query(name, dns.TypeCAA, c.Resolvers[0], true)
		if err != nil {
			return CAAInfo{Owner: name, Problem: CAALookupFailure, Detail: fmt.Sprintf("CAA query for %s: %v", name, err)}
		}
		var issue, issuewild []*dns.CAA
		any := false
		for _, rr := range rrs {
			// CAA lookups follow CNAMEs (RFC 8659), so the set may be owned
			// by an alias target rather than name itself.
			if caa, ok := rr.(*dns.CAA); ok {
				any = true
				switch strings.ToLower(caa.Tag) {
				case "issue":
					issue = append(issue, caa)
				case "issuewild":
					issuewild = append(issuewild, caa)
				}
			}
		}
		if !any {
			continue
		}
		info := CAAInfo{Owner: name, Tag: "issue"}
		set := issue
		if wildcard && len(issuewild) > 0 {
			set, info.Tag = issuewild, "issuewild"
		}
		for _, r := range set {
			info.Records = append(info.Records, r.Value)
		}
		if len(issue) == 0 && len(issuewild) == 0 {
			info.Detail = fmt.Sprintf("CAA at %s has no issue/issuewild properties; any CA may issue", name)
			return info
		}
		return c.evaluate(info, set)
	}
	return CAAInfo{Detail: "no CAA records; any CA may issue"}
}

func (c *Checker) evaluate(info CAAInfo, set []*dns.CAA) CAAInfo {
	if len(set) == 0 {
		info.Problem = CAANoIssuers
		info.Detail = fmt.Sprintf("CAA at %s has no %s property, so no CA may issue", info.Owner, info.Tag)
		return info
	}
	// Any one matching record permits issuance.
	problem, detail := CAANotPermitted,
		fmt.Sprintf("CAA at %s does not permit %s (%s: %s)", info.Owner, strings.Join(c.CAAIdentifiers, ", "), info.Tag, strings.Join(info.Records, " | "))
	for _, caa := range set {
		issuer, params := parseCAAValue(caa.Value)
		if !slices.Contains(c.CAAIdentifiers, issuer) {
			continue
		}
		uri, pinned := params["accounturi"]
		if pinned && c.AccountURI != "" && uri != c.AccountURI {
			problem, detail = CAAOtherAccount, fmt.Sprintf("CAA at %s pins %s to account %s, ours is %s", info.Owner, issuer, uri, c.AccountURI)
			continue
		}
		if vm, ok := params["validationmethods"]; ok && !slices.Contains(strings.Split(vm, ","), "dns-01") {
			problem, detail = CAAMethods, fmt.Sprintf("CAA at %s limits %s to validation methods %q, which excludes dns-01", info.Owner, issuer, vm)
			continue
		}
		info.Problem = CAANone
		info.PinnedToUs = pinned && c.AccountURI != "" && uri == c.AccountURI
		info.Detail = fmt.Sprintf("CAA at %s permits %s (%s %q)", info.Owner, issuer, info.Tag, caa.Value)
		return info
	}
	info.Problem, info.Detail = problem, detail
	return info
}

// ChallengeInfo describes the state of a domain's _acme-challenge name.
type ChallengeInfo struct {
	Name string // _acme-challenge.<base>, no trailing dot
	Zone string // the partner zone containing Name ("" if not found)
	Want string // expected CNAME target, FQDN with trailing dot
	// Public maps each recursive resolver to the CNAME target it returned ("" for none).
	Public    map[string]string
	PublicErr map[string]error
	// Auth maps each authoritative nameserver to its answer ("" for none).
	Auth    map[string]string
	AuthErr map[string]error
	// ExistingTXT are TXT records at Name on the authoritative servers.
	// They conflict with the CNAME and must be removed.
	ExistingTXT []string
}

// Delegated reports whether every authoritative server and every public
// resolver returns the expected CNAME.
func (ci ChallengeInfo) Delegated() bool { return ci.AuthOK() && ci.PublicOK() }

func (ci ChallengeInfo) AuthOK() bool {
	if len(ci.Auth) == 0 {
		return false
	}
	for _, v := range ci.Auth {
		if v != ci.Want {
			return false
		}
	}
	return true
}

func (ci ChallengeInfo) PublicOK() bool {
	for _, v := range ci.Public {
		if v != ci.Want {
			return false
		}
	}
	return len(ci.PublicErr) == 0
}

// AuthWrongTarget returns a target the partner's servers return that isn't
// the expected one, or "".
func (ci ChallengeInfo) AuthWrongTarget() string {
	for _, v := range ci.Auth {
		if v != "" && v != ci.Want {
			return v
		}
	}
	return ""
}

// Challenge inspects the _acme-challenge name for domain.
func (c *Checker) Challenge(domain, wantCNAME string) ChallengeInfo {
	c.defaults()
	base := strings.TrimPrefix(domain, "*.")
	ci := ChallengeInfo{
		Name: "_acme-challenge." + base, Want: dns.Fqdn(strings.ToLower(wantCNAME)),
		Public: map[string]string{}, PublicErr: map[string]error{},
		Auth: map[string]string{}, AuthErr: map[string]error{},
	}
	for _, r := range c.Resolvers {
		got, err := c.cname(ci.Name, r, true)
		if err != nil {
			ci.PublicErr[r] = err
			continue
		}
		ci.Public[r] = got
	}
	// Find the zone from the hostname, not the _acme-challenge name: a
	// recursive SOA lookup of that name would follow the CNAME and query the
	// delegate label, which may cache NXDOMAIN there (see package dodns).
	zone, err := c.findZone(base)
	if err != nil {
		ci.AuthErr["(zone)"] = err
		return ci
	}
	ci.Zone = zone
	servers, err := c.zoneServers(zone)
	if err != nil {
		ci.AuthErr["(nameservers)"] = err
		return ci
	}
	for _, ns := range servers {
		got, err := c.cnameAny(ci.Name, ns.addrs)
		if err != nil {
			ci.AuthErr[ns.name] = err
			continue
		}
		ci.Auth[ns.name] = got
		if got == "" && ci.ExistingTXT == nil {
			for _, a := range ns.addrs {
				if rrs, err := c.query(ci.Name, dns.TypeTXT, a, false); err == nil {
					for _, rr := range rrs {
						if t, ok := rr.(*dns.TXT); ok {
							ci.ExistingTXT = append(ci.ExistingTXT, strings.Join(t.Txt, ""))
						}
					}
					break
				}
			}
		}
	}
	return ci
}

// HostInfo describes what a hostname resolves to.
type HostInfo struct {
	CNAME string // set if the hostname is an alias
	Addrs []string
	Err   error
}

func (c *Checker) Host(host string) HostInfo {
	c.defaults()
	var hi HostInfo
	if cn, err := c.cname(host, c.Resolvers[0], true); err == nil {
		hi.CNAME = strings.TrimSuffix(cn, ".")
	}
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rrs, err := c.query(host, qt, c.Resolvers[0], true)
		if err != nil {
			hi.Err = err
			continue
		}
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.A:
				hi.Addrs = append(hi.Addrs, v.A.String())
			case *dns.AAAA:
				hi.Addrs = append(hi.Addrs, v.AAAA.String())
			}
		}
	}
	return hi
}

func (c *Checker) defaults() {
	if c.AuthPort == "" {
		c.AuthPort = "53"
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
}
