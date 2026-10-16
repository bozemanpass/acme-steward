// Package onboard turns the live DNS state of a partner's hostnames into
// the steps the partner must take, rendered as plain text suitable for
// forwarding by email, and into a readiness summary for verification.
package onboard

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/bozemanpass/acme-steward/internal/dnscheck"
	"github.com/bozemanpass/acme-steward/internal/label"
)

// Pin policies for CAA accounturi.
const (
	PinOff      = "off"
	PinOptional = "optional"
	PinRequired = "required"
)

type Options struct {
	Organization string // who is asking, e.g. "Example Corp"
	Contact      string // where to reply
	CAIdentifier string // CAA issuer domain, e.g. "letsencrypt.org"
	CAName       string // e.g. "Let's Encrypt"
	AccountURI   string // our ACME account; "" if not registered yet
	Pin          string // PinOff, PinOptional or PinRequired
	TTL          int
	Now          time.Time
}

// Host is the observed DNS state of one challenge name: a base domain and,
// possibly, its wildcard.
type Host struct {
	Base      string   // e.g. sync.partner.com
	Domains   []string // configured forms: base and/or *.base
	Target    string   // expected CNAME target, no trailing dot
	Challenge dnscheck.ChallengeInfo
	CAA       []dnscheck.CAAInfo // one per entry in Domains
	Info      dnscheck.HostInfo
}

// Analyze looks up the DNS state for a certificate's domains. targets maps
// each base domain to its expected CNAME target.
func Analyze(c *dnscheck.Checker, domains []string, targets map[string]string) []Host {
	var hosts []Host
	idx := map[string]int{}
	for _, d := range domains {
		b := label.BaseDomain(d)
		i, ok := idx[b]
		if !ok {
			i = len(hosts)
			idx[b] = i
			hosts = append(hosts, Host{Base: b, Target: targets[b]})
		}
		hosts[i].Domains = append(hosts[i].Domains, d)
	}
	for i := range hosts {
		h := &hosts[i]
		h.Challenge = c.Challenge(h.Base, h.Target)
		for _, d := range h.Domains {
			h.CAA = append(h.CAA, c.CAA(d))
		}
		h.Info = c.Host(h.Base)
	}
	return hosts
}

// Need says whether a step requires action from the partner.
type Need int

const (
	Required Need = iota
	Optional
)

type Step struct {
	Kind  string // "cname", "caa", "caa-pin"
	Host  string
	Need  Need
	Done  bool
	Title string
	// Pending explains, for verification, what is still wrong.
	Pending string
	body    func(w *writer)
	verify  func(w *writer)
}

// Steps works out what the partner must do for each host.
func Steps(hosts []Host, o Options) []Step {
	var steps []Step
	for _, h := range hosts {
		steps = append(steps, cnameStep(h, o))
		if s, ok := caaStep(h, o); ok {
			steps = append(steps, s)
		}
	}
	return steps
}

// Ready reports whether every required step is done.
func Ready(steps []Step) bool {
	for _, s := range steps {
		if s.Need == Required && !s.Done {
			return false
		}
	}
	return true
}

func zoneOf(h Host) string {
	if h.Challenge.Zone != "" {
		return h.Challenge.Zone
	}
	// Unknown zone: fall back to the registrable-looking parent.
	parts := strings.Split(h.Base, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return h.Base
}

func relative(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func names(h Host) string {
	if len(h.Domains) == 1 {
		return h.Domains[0]
	}
	return strings.Join(h.Domains, " and ")
}

func cnameStep(h Host, o Options) Step {
	ci := h.Challenge
	zone := zoneOf(h)
	s := Step{Kind: "cname", Host: h.Base, Need: Required, Done: ci.Delegated(),
		Title: "Add a CNAME record for " + h.Base}
	wrong := ci.AuthWrongTarget()
	switch {
	case s.Done:
	case len(ci.ExistingTXT) > 0:
		s.Pending = fmt.Sprintf("%s has TXT records that must be deleted, and no CNAME", ci.Name)
	case wrong != "":
		s.Pending = fmt.Sprintf("%s points to %s instead of %s", ci.Name, strings.TrimSuffix(wrong, "."), h.Target)
	case ci.AuthOK():
		s.Pending = "the record is in place on the partner's DNS servers but not yet visible everywhere; waiting for caches to expire"
	default:
		s.Pending = fmt.Sprintf("no CNAME record at %s yet", ci.Name)
	}
	s.body = func(w *writer) {
		w.para("In the DNS zone %s, add this record:", zone)
		w.record([][2]string{
			{"Name (host)", relative(ci.Name, zone)},
			{"Type", "CNAME"},
			{"Value (target)", h.Target + "."},
			{"TTL", fmt.Sprintf("%d (or your usual default)", o.TTL)},
		})
		w.para("The full name of this record is %s. Some DNS control panels expect only the part shown under \"Name (host)\" and add the zone name themselves; others expect the full name. Some require the trailing dot on the value; others add it automatically.", ci.Name)
		if len(ci.ExistingTXT) > 0 {
			w.para("IMPORTANT: there are currently TXT records at %s, probably left over from an earlier certificate setup. A CNAME cannot coexist with other records at the same name, so please delete those TXT records first.", ci.Name)
		}
		if wrong != "" {
			w.para("IMPORTANT: there is already a CNAME record at %s, but it points to %s. Please change its value to the one above.", ci.Name, strings.TrimSuffix(wrong, "."))
		}
		w.para("Please keep this record for as long as we provide service for %s. If it is removed, certificate renewals will fail and visitors will eventually see certificate errors.", h.Base)
		w.para("What this record does: it lets us prove to %s that we are authorised to obtain certificates for %s and *.%s. It gives us no access to your DNS zone and no control over any other name.", o.CAName, h.Base, h.Base)
	}
	s.verify = func(w *writer) {
		w.code("dig +short CNAME " + ci.Name)
		w.para("should print exactly:")
		w.code(h.Target + ".")
	}
	return s
}

// caaStep decides whether CAA needs attention for a host.
func caaStep(h Host, o Options) (Step, bool) {
	var blocking *dnscheck.CAAInfo
	pinned, anyCAA := true, false
	for i := range h.CAA {
		c := &h.CAA[i]
		if c.Owner != "" {
			anyCAA = true
		}
		if !c.Permitted() && c.Problem != dnscheck.CAALookupFailure && blocking == nil {
			blocking = c
		}
		if !c.PinnedToUs {
			pinned = false
		}
	}
	alias := h.Info.CNAME != ""
	canPin := o.AccountURI != "" && o.Pin != PinOff && !alias

	s := Step{Kind: "caa", Host: h.Base, Need: Required}
	value := o.CAIdentifier
	pinValue := fmt.Sprintf("%s; accounturi=%s; validationmethods=dns-01", o.CAIdentifier, o.AccountURI)
	switch {
	case blocking != nil:
		s.Title = fmt.Sprintf("Allow %s in the CAA records for %s", o.CAName, h.Base)
		s.Pending = blocking.Detail
		if o.Pin == PinRequired && canPin {
			value = pinValue
		}
	case o.Pin == PinRequired && !pinned:
		s.Title = fmt.Sprintf("Restrict certificates for %s to our account (CAA)", h.Base)
		s.Pending = "no CAA record pinning issuance to our account"
		value = pinValue
		if !canPin {
			s.Pending += " (cannot be requested: " + pinBlocker(o, alias) + ")"
		}
	case o.Pin == PinOptional && canPin && !pinned:
		s.Kind, s.Need, s.Done = "caa-pin", Optional, false
		s.Title = fmt.Sprintf("Restrict certificates for %s to our account (CAA)", h.Base)
		value = pinValue
	default:
		return Step{}, false
	}

	tags := []string{"issue"}
	for _, c := range h.CAA {
		if c.Tag == "issuewild" && c.Owner == h.Base {
			tags = append(tags, "issuewild")
			break
		}
	}
	zone := zoneOf(h)
	s.body = func(w *writer) {
		switch {
		case blocking != nil && blocking.Problem == dnscheck.CAAOtherAccount:
			w.para("Your CAA records at %s allow %s to issue certificates only to a different account than ours, so %s would refuse to issue our certificate.", blocking.Owner, o.CAName, o.CAName)
		case blocking != nil && blocking.Problem == dnscheck.CAAMethods:
			w.para("Your CAA records at %s allow %s to issue certificates only with validation methods that exclude DNS validation (dns-01), which is the method we use.", blocking.Owner, o.CAName)
		case blocking != nil:
			w.para("Your domain publishes CAA records (at %s). These list the certificate authorities allowed to issue certificates for it, and %s is not currently among them, so it would refuse to issue our certificate.", blocking.Owner, o.CAName)
		case s.Need == Optional:
			if anyCAA {
				w.para("Your CAA records already allow %s, so no CAA change is required. You may optionally add the record below.", o.CAName)
			} else {
				w.para("Your domain does not publish CAA records, so no CAA change is required. You may optionally add the record below.")
			}
			w.para("It allows %s to issue certificates for %s only to our account, and only after DNS validation. This protects you against anyone else obtaining a certificate for this name, including through misuse of the record in the previous step.", o.CAName, h.Base)
		default:
			w.para("Please add the record below. It allows %s to issue certificates for %s only to our account, and only after DNS validation.", o.CAName, h.Base)
		}
		if alias {
			if blocking == nil {
				w.para("Note: %s is an alias (CNAME) for %s, so a CAA record cannot be added at %s. Please contact us to discuss.", h.Base, h.Info.CNAME, h.Base)
				return
			}
			w.para("Note: %s is itself an alias (CNAME) for %s, so a CAA record cannot be added at %s. Instead, please add a record with tag \"issue\" and value \"%s\" alongside your existing CAA records at %s. Do not remove the existing records.", h.Base, h.Info.CNAME, h.Base, value, blocking.Owner)
			return
		}
		w.para("In the DNS zone %s, add:", zone)
		for _, tag := range tags {
			w.record([][2]string{
				{"Name (host)", relative(h.Base, zone)},
				{"Type", "CAA"},
				{"Flags", "0"},
				{"Tag", tag},
				{"Value", value},
			})
		}
		w.para("In zone-file form:")
		for _, tag := range tags {
			w.code(fmt.Sprintf("%s. CAA 0 %s \"%s\"", h.Base, tag, value))
		}
		if anyCAA && blocking != nil && blocking.Owner != h.Base {
			w.para("Because this record is added at %s itself, it applies only to that name. Your existing CAA records at %s continue to apply to every other name.", h.Base, blocking.Owner)
		} else {
			w.para("A CAA record at %s applies to that name only. Once it exists, only the certificate authorities it lists may issue certificates for %s.", h.Base, h.Base)
		}
		if value == pinValue {
			if s.Need == Optional {
				w.para("Some DNS providers (DigitalOcean, for example) do not accept the extra parameters in this value. If yours rejects it, simply skip this optional step.")
			} else {
				w.para("Some DNS providers (DigitalOcean, for example) do not accept the extra parameters in this value. If yours rejects it, please let us know rather than entering a different value.")
			}
			w.para("If you add this record and later stop using our service, please remove it at the same time as the CNAME record.")
		}
	}
	s.verify = func(w *writer) {
		if alias {
			return
		}
		w.code("dig +short CAA " + h.Base)
		w.para("should include:")
		w.code(fmt.Sprintf("0 issue \"%s\"", value))
	}
	return s, true
}

func pinBlocker(o Options, alias bool) string {
	switch {
	case o.AccountURI == "":
		return "our ACME account is not registered yet"
	case alias:
		return "the hostname is an alias (CNAME)"
	}
	return "pinning is turned off"
}

// RenderInstructions writes the partner-facing instructions.
func RenderInstructions(out io.Writer, certName string, hosts []Host, steps []Step, o Options) {
	w := &writer{out: out}
	w.heading("DNS CHANGES REQUESTED", "=")
	var all []string
	zones := map[string]bool{}
	var zoneList []string
	for _, h := range hosts {
		all = append(all, h.Domains...)
		if z := zoneOf(h); !zones[z] {
			zones[z] = true
			zoneList = append(zoneList, z)
		}
	}
	w.field("For", all)
	if o.Organization != "" {
		w.field("Requested by", []string{o.Organization})
	}
	w.field("Reference", []string{certName + " / " + o.Now.Format("2006-01-02")})
	w.line("")

	who := "We"
	if o.Organization != "" {
		who = o.Organization
	}
	w.para("%s will obtain the TLS (HTTPS) certificate for the name(s) above from %s, and renew it automatically. %s requires proof that we are authorised to do this. The DNS change below delegates that proof to us. It is a one-time change: renewals need no further action from you.", who, o.CAName, o.CAName)

	required := 0
	var pendingZones []string
	for _, s := range steps {
		if s.Need == Required && !s.Done {
			required++
			for _, h := range hosts {
				if z := zoneOf(h); h.Base == s.Host && !slices.Contains(pendingZones, z) {
					pendingZones = append(pendingZones, z)
				}
			}
		}
	}
	if required == 0 {
		w.para("All required changes are already in place in %s. No action is needed, apart from any optional step below.", strings.Join(zoneList, ", "))
	} else {
		w.para("Please make the change(s) marked REQUIRED in the DNS zone %s, then reply to let us know. We will verify them from our side.", strings.Join(pendingZones, ", "))
	}

	for i, s := range steps {
		tag := "REQUIRED"
		switch {
		case s.Done:
			tag = "ALREADY DONE - no action needed"
		case s.Need == Optional:
			tag = "OPTIONAL, RECOMMENDED"
		}
		w.heading(fmt.Sprintf("STEP %d (%s): %s", i+1, tag, s.Title), "-")
		if !s.Done {
			s.body(w)
		}
	}

	if caaInfo := caaNoChange(hosts, steps); len(caaInfo) > 0 {
		w.heading("CAA RECORDS", "-")
		for _, line := range caaInfo {
			w.para("%s", line)
		}
	}

	w.heading("HOW TO CHECK (optional)", "-")
	w.para("After making the change(s), you can check them from any computer that has the \"dig\" tool:")
	for i, s := range steps {
		if !s.Done && s.verify != nil {
			if s.Need == Optional {
				w.para("If you added the optional record in step %d:", i+1)
			}
			s.verify(w)
		}
	}
	w.para("Changes can take anywhere from a few minutes to an hour or more (the record's TTL) to become visible everywhere.")
	if o.Contact != "" {
		w.heading("QUESTIONS", "-")
		w.para("Please contact %s.", o.Contact)
	}
}

func caaNoChange(hosts []Host, steps []Step) []string {
	has := map[string]bool{}
	for _, s := range steps {
		if s.Kind != "cname" {
			has[s.Host] = true
		}
	}
	var out []string
	for _, h := range hosts {
		if has[h.Base] {
			continue
		}
		owner := ""
		for _, c := range h.CAA {
			if c.Owner != "" {
				owner = c.Owner
			}
		}
		if owner == "" {
			out = append(out, fmt.Sprintf("%s: no change needed (your domain does not publish CAA records).", h.Base))
		} else {
			out = append(out, fmt.Sprintf("%s: no change needed (your CAA records at %s already allow our certificate authority).", h.Base, owner))
		}
	}
	return out
}

// RenderSummary writes a plain-English readiness summary for us.
func RenderSummary(out io.Writer, certName string, steps []Step) {
	w := &writer{out: out}
	state := "READY"
	if !Ready(steps) {
		state = "NOT READY"
	}
	w.line(fmt.Sprintf("%s: %s", certName, state))
	for i, s := range steps {
		status := "done"
		switch {
		case !s.Done && s.Need == Optional:
			status = "optional, not done"
		case !s.Done:
			status = "PENDING: " + s.Pending
		}
		w.line(fmt.Sprintf("  step %d, %s: %s", i+1, s.Title, status))
	}
}

// writer produces plain ASCII text wrapped at 72 columns.
type writer struct{ out io.Writer }

const width = 72

func (w *writer) line(s string) { fmt.Fprintln(w.out, s) }

func (w *writer) heading(s, underline string) {
	w.line("")
	w.line(s)
	w.line(strings.Repeat(underline, min(len(s), width)))
	w.line("")
}

func (w *writer) field(name string, values []string) {
	for i, v := range values {
		k := ""
		if i == 0 {
			k = name + ":"
		}
		w.line(fmt.Sprintf("%-14s %s", k, v))
	}
}

func (w *writer) para(format string, a ...any) {
	words := strings.Fields(fmt.Sprintf(format, a...))
	cur := ""
	for _, word := range words {
		if cur != "" && len(cur)+1+len(word) > width {
			w.line(cur)
			cur = word
			continue
		}
		if cur != "" {
			cur += " "
		}
		cur += word
	}
	if cur != "" {
		w.line(cur)
	}
	w.line("")
}

func (w *writer) record(fields [][2]string) {
	for _, f := range fields {
		w.line(fmt.Sprintf("    %-16s %s", f[0]+":", f[1]))
	}
	w.line("")
}

func (w *writer) code(s string) {
	w.line("    " + s)
	w.line("")
}
