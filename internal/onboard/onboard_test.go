package onboard

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bozemanpass/acme-steward/internal/dnscheck"
)

const (
	target  = "sync-partner-com-abc.acme.example.net"
	account = "https://ca.example/acct/1"
)

func opts(pin, acct string) Options {
	return Options{Organization: "Example Corp", Contact: "certs@example.net", CAIdentifier: "letsencrypt.org",
		CAName: "Let's Encrypt", AccountURI: acct, Pin: pin, TTL: 3600, Now: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
}

func challenge(auth, public string, txt ...string) dnscheck.ChallengeInfo {
	return dnscheck.ChallengeInfo{Name: "_acme-challenge.sync.partner.com", Zone: "partner.com", Want: target + ".",
		Auth: map[string]string{"ns1.partner.com": auth}, Public: map[string]string{"1.1.1.1:53": public}, ExistingTXT: txt}
}

func host(ci dnscheck.ChallengeInfo, caa dnscheck.CAAInfo) Host {
	return Host{Base: "sync.partner.com", Domains: []string{"sync.partner.com"}, Target: target, Challenge: ci, CAA: []dnscheck.CAAInfo{caa}}
}

func render(t *testing.T, hosts []Host, o Options) (string, []Step) {
	t.Helper()
	steps := Steps(hosts, o)
	var b bytes.Buffer
	RenderInstructions(&b, "partner-a", hosts, steps, o)
	text := b.String()
	for i, line := range strings.Split(text, "\n") {
		for _, r := range line {
			if r > 126 {
				t.Errorf("line %d has non-ASCII character %q: %s", i+1, r, line)
			}
		}
		// Prose wraps at 72; indented records/commands and headings may not.
		if len(line) > width && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "STEP") && !strings.HasPrefix(line, "---") {
			t.Errorf("line %d too long (%d): %s", i+1, len(line), line)
		}
	}
	return text, steps
}

func kinds(steps []Step) string {
	var k []string
	for _, s := range steps {
		state := "todo"
		if s.Done {
			state = "done"
		} else if s.Need == Optional {
			state = "optional"
		}
		k = append(k, s.Kind+":"+state)
	}
	return strings.Join(k, ",")
}

func TestScenarios(t *testing.T) {
	want := target + "."
	noCAA := dnscheck.CAAInfo{}
	permits := dnscheck.CAAInfo{Owner: "partner.com", Tag: "issue", Records: []string{"letsencrypt.org"}}
	pinned := dnscheck.CAAInfo{Owner: "sync.partner.com", Tag: "issue", PinnedToUs: true}
	blocked := dnscheck.CAAInfo{Owner: "partner.com", Tag: "issue", Problem: dnscheck.CAANotPermitted, Detail: "CAA at partner.com does not permit letsencrypt.org"}
	other := dnscheck.CAAInfo{Owner: "partner.com", Tag: "issue", Problem: dnscheck.CAAOtherAccount, Detail: "pinned elsewhere"}

	tests := []struct {
		name     string
		h        Host
		o        Options
		steps    string
		ready    bool
		contains []string
		absent   []string
	}{
		{"fresh, no CAA, no account", host(challenge("", ""), noCAA), opts(PinOptional, ""),
			"cname:todo", false,
			[]string{"STEP 1 (REQUIRED)", "Name (host):     _acme-challenge.sync", "Value (target):  " + want,
				"in the DNS zone partner.com", "no change needed (your domain does not publish CAA records)",
				"dig +short CNAME _acme-challenge.sync.partner.com", "Please contact certs@example.net"},
			[]string{"accounturi"}},
		{"fresh, CAA permits, pin offered", host(challenge("", ""), permits), opts(PinOptional, account),
			"cname:todo,caa-pin:optional", false,
			[]string{"STEP 2 (OPTIONAL, RECOMMENDED)", "Your CAA records already allow Let's Encrypt",
				"letsencrypt.org; accounturi=" + account + "; validationmethods=dns-01", "If you added the optional record in step 2",
				"If yours rejects it, simply skip this optional step"},
			nil},
		{"CAA blocks", host(challenge("", ""), blocked), opts(PinOptional, account),
			"cname:todo,caa:todo", false,
			[]string{"STEP 2 (REQUIRED): Allow Let's Encrypt", "sync.partner.com. CAA 0 issue \"letsencrypt.org\"",
				"Your existing CAA records at partner.com continue to apply"},
			[]string{"accounturi"}},
		{"CAA pinned to another account", host(challenge(want, want), other), opts(PinOptional, account),
			"cname:done,caa:todo", false,
			[]string{"STEP 1 (ALREADY DONE", "only to a different account than ours"}, nil},
		{"left-over TXT", host(challenge("", "", "old"), noCAA), opts(PinOff, ""),
			"cname:todo", false,
			[]string{"please delete those TXT records first"}, nil},
		{"wrong target", host(challenge("old.example.org.", "old.example.org."), noCAA), opts(PinOff, ""),
			"cname:todo", false,
			[]string{"it points to old.example.org. Please change"}, nil},
		{"propagating", host(challenge(want, ""), noCAA), opts(PinOff, ""),
			"cname:todo", false, nil, nil},
		{"complete", host(challenge(want, want), pinned), opts(PinRequired, account),
			"cname:done", true,
			[]string{"All required changes are already in place"}, []string{"Please make the change"}},
		{"pin required, not pinned", host(challenge(want, want), permits), opts(PinRequired, account),
			"cname:done,caa:todo", false,
			[]string{"STEP 2 (REQUIRED): Restrict certificates", "accounturi=" + account}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text, steps := render(t, []Host{tc.h}, tc.o)
			flat := strings.Join(strings.Fields(text), " ") // ignore line wrapping
			if got := kinds(steps); got != tc.steps {
				t.Errorf("steps = %s, want %s", got, tc.steps)
			}
			if Ready(steps) != tc.ready {
				t.Errorf("ready = %v", Ready(steps))
			}
			for _, c := range tc.contains {
				if !strings.Contains(text, c) && !strings.Contains(flat, strings.Join(strings.Fields(c), " ")) {
					t.Errorf("missing %q in:\n%s", c, text)
				}
			}
			for _, c := range tc.absent {
				if strings.Contains(text, c) {
					t.Errorf("unexpected %q in:\n%s", c, text)
				}
			}
		})
	}
}

func TestSummaryPending(t *testing.T) {
	want := target + "."
	steps := Steps([]Host{host(challenge(want, ""), dnscheck.CAAInfo{})}, opts(PinOff, ""))
	var b bytes.Buffer
	RenderSummary(&b, "partner-a", steps)
	if !strings.Contains(b.String(), "partner-a: NOT READY") || !strings.Contains(b.String(), "not yet visible everywhere") {
		t.Error(b.String())
	}
}

func TestWildcardIssuewild(t *testing.T) {
	h := Host{Base: "sync.partner.com", Domains: []string{"sync.partner.com", "*.sync.partner.com"}, Target: target,
		Challenge: challenge("", ""),
		CAA: []dnscheck.CAAInfo{
			{Owner: "sync.partner.com", Tag: "issue", Problem: dnscheck.CAANotPermitted},
			{Owner: "sync.partner.com", Tag: "issuewild", Problem: dnscheck.CAANotPermitted},
		}}
	text, _ := render(t, []Host{h}, opts(PinOff, ""))
	for _, want := range []string{`CAA 0 issue "letsencrypt.org"`, `CAA 0 issuewild "letsencrypt.org"`, "*.sync.partner.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
}
