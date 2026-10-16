package label

import (
	"strings"
	"testing"
)

func TestDerive(t *testing.T) {
	a := Derive("sync.partner.com")
	if !strings.HasPrefix(a, "sync-partner-com-") || len(a) != len("sync-partner-com-")+hashLen {
		t.Fatalf("unexpected label %q", a)
	}
	if Derive("SYNC.Partner.com.") != a || Derive("*.sync.partner.com") != a {
		t.Fatal("label must ignore case, trailing dot and wildcard")
	}
	// Readable parts collide; hashes must not.
	if Derive("a-b.example.com") == Derive("a.b-example.com") {
		t.Fatal("ambiguous domains produced the same label")
	}
	long := strings.Repeat("abcdefghij.", 9) + "com"
	l := Derive(long)
	if len(l) > 63 || strings.Contains(l, "--") && strings.HasSuffix(strings.Split(l, "--")[0], "-") {
		t.Fatalf("label too long or malformed: %q (%d)", l, len(l))
	}
	if Target(a, "Acme.Example.NET.") != a+".acme.example.net" {
		t.Fatal(Target(a, "Acme.Example.NET."))
	}
	if ChallengeName("*.x.example.com") != "_acme-challenge.x.example.com" {
		t.Fatal(ChallengeName("*.x.example.com"))
	}
}
