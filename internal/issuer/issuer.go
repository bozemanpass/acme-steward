// Package issuer obtains certificates from an ACME CA with lego, using
// DNS-01 challenges written to a DigitalOcean-hosted delegate zone that the
// domains' _acme-challenge names are CNAMEd into.
package issuer

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/registration"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/store"
)

var keyTypes = map[string]certcrypto.KeyType{
	"ec256":   certcrypto.EC256,
	"ec384":   certcrypto.EC384,
	"rsa2048": certcrypto.RSA2048,
	"rsa3072": certcrypto.RSA3072,
	"rsa4096": certcrypto.RSA4096,
}

// RouteLegoLogs sends lego's own log output through slog.
func RouteLegoLogs(h slog.Handler) {
	legolog.Logger = slog.NewLogLogger(h.WithAttrs([]slog.Attr{slog.String("component", "lego")}), slog.LevelInfo)
}

// ExtraDNSOptions are appended to the DNS-01 challenge options. It is a
// test hook (e.g. to skip authoritative propagation checks on port 53).
var ExtraDNSOptions []dns01.ChallengeOption

type account struct {
	Email        string                 `json:"email,omitempty"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

type Issuer struct {
	cfg      *config.Config
	store    *store.Store
	log      *slog.Logger
	account  *account
	provider challenge.Provider
	clients  map[string]*lego.Client // by key type, created on demand
}

func (iss *Issuer) client(keyType string) (*lego.Client, error) {
	if c := iss.clients[keyType]; c != nil {
		return c, nil
	}
	lc := lego.NewConfig(iss.account)
	lc.CADirURL = iss.cfg.CADirectory
	lc.Certificate.KeyType = keyTypes[keyType]
	lc.UserAgent = "acme-steward"
	c, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("ACME client for %s: %w", iss.cfg.CADirectory, err)
	}
	if iss.provider != nil {
		if err := c.Challenge.SetDNS01Provider(iss.provider,
			append([]dns01.ChallengeOption{dns01.AddRecursiveNameservers(iss.cfg.DNS.Resolvers)}, ExtraDNSOptions...)...); err != nil {
			return nil, err
		}
	}
	iss.clients[keyType] = c
	return c, nil
}

// New loads or creates the ACME account. DNS-01 is configured only when
// doToken is non-empty (it is not needed for ARI queries).
func New(cfg *config.Config, st *store.Store, doToken string, log *slog.Logger) (*Issuer, error) {
	iss := &Issuer{cfg: cfg, store: st, log: log, clients: map[string]*lego.Client{}}
	acct, err := iss.loadAccount()
	if err != nil {
		return nil, err
	}
	iss.account = acct

	var provider challenge.Provider
	if doToken != "" {
		dc := digitalocean.NewDefaultConfig()
		dc.AuthToken = doToken
		dc.TTL = cfg.DNS.TTL
		dc.PropagationTimeout = cfg.DNS.PropagationTimeout.D()
		do, err := digitalocean.NewDNSProviderConfig(dc)
		if err != nil {
			return nil, err
		}
		provider = &delegatedProvider{inner: do, zone: cfg.DNS.DelegateZone}
	}

	iss.provider = provider

	if acct.Registration == nil {
		if err := iss.register(); err != nil {
			return nil, err
		}
	}
	return iss, nil
}

func (iss *Issuer) loadAccount() (*account, error) {
	acct := &account{Email: iss.cfg.ACME.Email}
	keyPath := iss.store.AccountKeyPath()
	kb, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		if acct.key, err = certcrypto.ParsePEMPrivateKey(kb); err != nil {
			return nil, fmt.Errorf("%s: %w", keyPath, err)
		}
	case errors.Is(err, os.ErrNotExist):
		if acct.key, err = certcrypto.GeneratePrivateKey(certcrypto.EC256); err != nil {
			return nil, err
		}
		if err := store.WriteFileAtomic(keyPath, certcrypto.PEMEncode(acct.key), 0o600); err != nil {
			return nil, err
		}
		iss.log.Info("created ACME account key", "event", "account.key_created", "path", keyPath)
	default:
		return nil, err
	}

	jb, err := os.ReadFile(iss.store.AccountJSONPath())
	if err == nil {
		var saved account
		if err := json.Unmarshal(jb, &saved); err != nil {
			return nil, err
		}
		// An account registered against a different CA is not reusable.
		if saved.Registration != nil && sameCA(saved.Registration.URI, iss.cfg.CADirectory) {
			acct.Registration = saved.Registration
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return acct, nil
}

func sameCA(accountURI, directory string) bool {
	host := func(u string) string {
		u = strings.TrimPrefix(u, "https://")
		h, _, _ := strings.Cut(u, "/")
		return h
	}
	return host(accountURI) == host(directory)
}

func (iss *Issuer) register() error {
	c, err := iss.client("ec256")
	if err != nil {
		return err
	}
	reg := c.Registration
	res, err := reg.ResolveAccountByKey()
	if err != nil {
		if !iss.cfg.ACME.AcceptTerms {
			return errors.New("no ACME account is registered; set acme.accept_terms: true to agree to the CA's terms of service and register")
		}
		res, err = reg.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("ACME registration: %w", err)
		}
		iss.log.Info("registered ACME account", "event", "account.registered", "account_uri", res.URI, "ca", iss.cfg.CADirectory)
	} else {
		iss.log.Info("found existing ACME account for key", "event", "account.resolved", "account_uri", res.URI)
	}
	iss.account.Registration = res
	b, _ := json.MarshalIndent(iss.account, "", "  ")
	return store.WriteFileAtomic(iss.store.AccountJSONPath(), b, 0o600)
}

// AccountURI identifies our ACME account (for CAA accounturi pinning).
func (iss *Issuer) AccountURI() string { return iss.account.Registration.URI }

// Obtain orders a new certificate with a freshly generated key. If
// replacing is non-nil it is passed to the CA as the certificate being
// replaced (RFC 9773), which lets the CA exempt it from some rate limits.
func (iss *Issuer) Obtain(ct *config.Certificate, replacing *x509.Certificate) (*store.Bundle, error) {
	client, err := iss.client(ct.KeyType)
	if err != nil {
		return nil, err
	}
	req := certificate.ObtainRequest{Domains: ct.Domains, Bundle: true, Profile: ct.Profile}
	if replacing != nil {
		if id, err := certificate.MakeARICertID(replacing); err == nil {
			req.ReplacesCertID = id
		}
	}
	// Each order is a fresh lookup of the delegation and zone.
	dns01.ClearFqdnCache()
	res, err := client.Certificate.Obtain(req)
	if err != nil && req.ReplacesCertID != "" && strings.Contains(err.Error(), "alreadyReplaced") {
		req.ReplacesCertID = ""
		res, err = client.Certificate.Obtain(req)
	}
	if err != nil {
		return nil, err
	}
	leaf, chain := splitBundle(res.Certificate)
	if len(chain) == 0 {
		chain = res.IssuerCertificate
	}
	return &store.Bundle{
		Name: ct.Name, KeyType: ct.KeyType, Profile: ct.Profile, CertURL: res.CertURL,
		Domains: ct.Domains, Key: res.PrivateKey, Cert: leaf, Chain: chain,
	}, nil
}

// RenewalInfo queries ARI for the certificate. It returns (nil, nil) if
// the CA does not support ARI.
func (iss *Issuer) RenewalInfo(leaf *x509.Certificate) (*certificate.RenewalInfoResponse, error) {
	c, err := iss.client("ec256")
	if err != nil {
		return nil, err
	}
	ri, err := c.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil && strings.Contains(err.Error(), "renewalInfo endpoint") {
		return nil, nil
	}
	return ri, err
}

func splitBundle(b []byte) (leaf, chain []byte) {
	rest := b
	first := true
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return leaf, chain
		}
		enc := pem.EncodeToMemory(blk)
		if first {
			leaf = enc
			first = false
		} else {
			chain = append(chain, enc...)
		}
	}
}

// delegatedProvider refuses to write challenge records anywhere except the
// delegate zone. Without it, a missing or wrong CNAME would make lego try
// to write into the partner's own zone (and fail later and less clearly).
type delegatedProvider struct {
	inner challenge.ProviderTimeout
	zone  string
}

func (p *delegatedProvider) delegated(domain, keyAuth string) (dns01.ChallengeInfo, string, bool) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	eff := strings.TrimSuffix(strings.ToLower(info.EffectiveFQDN), ".")
	return info, eff, strings.HasSuffix(eff, "."+p.zone)
}

func (p *delegatedProvider) Present(domain, token, keyAuth string) error {
	info, eff, ok := p.delegated(domain, keyAuth)
	if !ok {
		return fmt.Errorf("%s does not resolve via CNAME into delegate zone %s (effective name %s); check the partner's delegation record",
			strings.TrimSuffix(info.FQDN, "."), p.zone, eff)
	}
	return p.inner.Present(domain, token, keyAuth)
}

func (p *delegatedProvider) CleanUp(domain, token, keyAuth string) error {
	if _, _, ok := p.delegated(domain, keyAuth); !ok {
		return nil // Present wrote nothing
	}
	return p.inner.CleanUp(domain, token, keyAuth)
}

func (p *delegatedProvider) Timeout() (time.Duration, time.Duration) { return p.inner.Timeout() }
