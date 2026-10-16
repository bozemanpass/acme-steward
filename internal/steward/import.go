package steward

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	"fmt"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/label"
	"github.com/bozemanpass/acme-steward/internal/store"
)

// Import installs an existing certificate and key as a new current version,
// e.g. to distribute a partner's existing certificate before the first
// ACME issuance. certPEM may contain the full chain; chainPEM is optional.
// The next cycle renews it if it doesn't match the configuration (domains,
// key type) or is due.
func (s *Steward) Import(ct *config.Certificate, certPEM, keyPEM, chainPEM []byte) (*store.Manifest, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate and key do not form a valid pair: %w", err)
	}
	leaf := pair.Leaf
	leafPEM, rest := splitPEM(certPEM)
	if len(chainPEM) == 0 {
		chainPEM = rest
	}
	if len(chainPEM) == 0 {
		s.Log.Warn("importing a certificate without a chain", "event", "cert.import_no_chain", "cert", ct.Name)
	}

	var domains []string
	for _, d := range leaf.DNSNames {
		domains = append(domains, label.Normalize(d))
	}
	if !sameSet(domains, ct.Domains) {
		s.Log.Warn("imported certificate's names differ from the configured domains; it will be replaced on the next cycle",
			"event", "cert.import_mismatch", "cert", ct.Name, "cert_domains", domains, "configured", ct.Domains)
	}
	m, err := s.Store.Save(store.Bundle{
		Name: ct.Name, Domains: domains, KeyType: keyType(leaf.PublicKey), Profile: ct.Profile,
		Key: keyPEM, Cert: leafPEM, Chain: chainPEM,
	}, s.Now())
	if err != nil {
		return nil, err
	}
	s.Log.Info("certificate imported", "event", "cert.imported", "cert", ct.Name, "version", m.Version,
		"serial", m.Serial, "issuer", m.Issuer, "not_after", m.NotAfter)
	if _, err := s.Store.Prune(ct.Name, s.Cfg.Renewal.KeepVersions); err != nil {
		s.Log.Warn("pruning old versions", "event", "cert.prune_failed", "cert", ct.Name, "error", err)
	}
	return m, nil
}

func keyType(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ec%d", k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	}
	return "unknown"
}

// splitPEM returns the first PEM block and the remainder, re-encoded.
func splitPEM(b []byte) (first, rest []byte) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return first, rest
		}
		if first == nil {
			first = pem.EncodeToMemory(blk)
		} else {
			rest = append(rest, pem.EncodeToMemory(blk)...)
		}
	}
}
