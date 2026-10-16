// Package label derives the delegate-zone label that a domain's
// _acme-challenge CNAME points at.
package label

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

const (
	hashLen  = 8 // base32 chars = 40 bits
	maxLabel = 63
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// BaseDomain strips a leading wildcard and trailing dot and lowercases.
// "*.example.com" and "example.com" share one challenge name, so they share
// one label.
func BaseDomain(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	return strings.TrimPrefix(d, "*.")
}

// ChallengeName is the name the partner puts the CNAME on.
func ChallengeName(domain string) string {
	return "_acme-challenge." + BaseDomain(domain)
}

// Derive returns the delegate label for domain: a readable form of the
// domain followed by a short hash of it, e.g.
// "sync.partner.com" -> "sync-partner-com-k3x9q2ab".
//
// The readable part alone is ambiguous ("a-b.c" and "a.b-c" both become
// "a-b-c") and may exceed the 63-octet label limit, so the hash makes the
// label unique and the readable part is truncated as needed.
func Derive(domain string) string {
	d := BaseDomain(domain)
	sum := sha256.Sum256([]byte(d))
	h := b32.EncodeToString(sum[:])[:hashLen]
	readable := strings.ReplaceAll(d, ".", "-")
	if max := maxLabel - 1 - hashLen; len(readable) > max {
		readable = strings.TrimRight(readable[:max], "-")
	}
	return readable + "-" + h
}

// Target is the fully qualified CNAME target in the delegate zone.
func Target(lbl, zone string) string {
	return lbl + "." + strings.TrimSuffix(strings.ToLower(zone), ".")
}

// Normalize lowercases a domain and strips a trailing dot, keeping
// any leading wildcard.
func Normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
