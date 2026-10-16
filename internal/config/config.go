// Package config loads the acme-steward configuration file and environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment variables.
const (
	EnvConfig          = "ACME_STEWARD_CONFIG"
	EnvDataDir         = "ACME_STEWARD_DATA_DIR"
	EnvLogLevel        = "ACME_STEWARD_LOG_LEVEL"
	EnvLogFormat       = "ACME_STEWARD_LOG_FORMAT"
	EnvDOAuthToken     = "DO_AUTH_TOKEN"
	EnvDOAuthTokenFile = "DO_AUTH_TOKEN_FILE"
	EnvSSHKey          = "ACME_STEWARD_SSH_KEY"

	DefaultConfigPath = "/etc/acme-steward/config.yaml"
	DefaultDataDir    = "/var/lib/acme-steward"
)

// Well-known CA directory URLs that may be given by name.
var caDirectories = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}

// Duration is a time.Duration that also accepts a "d" (days) suffix in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// ParseDuration parses a Go duration string, additionally accepting "<n>d".
func ParseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return v, nil
}

type Config struct {
	ACME         ACME          `yaml:"acme"`
	DNS          DNS           `yaml:"dns"`
	Renewal      Renewal       `yaml:"renewal"`
	SSH          SSH           `yaml:"ssh"`
	Clusters     []Cluster     `yaml:"clusters"`
	Certificates []Certificate `yaml:"certificates"`
	Partner      Partner       `yaml:"partner_instructions"`

	// From the environment, not the file.
	DataDir       string `yaml:"-"`
	DOAuthToken   string `yaml:"-"`
	CADirectory   string `yaml:"-"` // resolved from ACME.CA
	clusterByName map[string]*Cluster
	sshKey        []byte // from ACME_STEWARD_SSH_KEY; see WriteSSHKey
}

type ACME struct {
	// Email is an optional account contact address.
	Email string `yaml:"email"`
	// CA is "letsencrypt", "letsencrypt-staging" or a directory URL.
	CA string `yaml:"ca"`
	// AcceptTerms must be true to register an account with the CA.
	AcceptTerms bool   `yaml:"accept_terms"`
	KeyType     string `yaml:"key_type"`
	Profile     string `yaml:"profile"`
}

type DNS struct {
	// DelegateZone is the zone (hosted at DigitalOcean) that partner
	// _acme-challenge CNAMEs point into.
	DelegateZone       string   `yaml:"delegate_zone"`
	Resolvers          []string `yaml:"resolvers"`
	PropagationTimeout Duration `yaml:"propagation_timeout"`
	// PropagationSettle is an extra wait after lego sees the challenge
	// record before the CA is asked to validate. The CA validates from
	// several vantage points, some of which may reach nameserver instances
	// still serving the previous TXT set. Default 90s; "0s" disables.
	PropagationSettle *Duration `yaml:"propagation_settle"`
	TTL               int       `yaml:"ttl"`
	// CAAIdentifiers are the issuer domain names accepted in CAA records.
	CAAIdentifiers []string `yaml:"caa_identifiers"`
}

type Renewal struct {
	// CheckInterval is how often the daemon wakes to renew and push.
	CheckInterval Duration `yaml:"check_interval"`
	// RenewRemaining is the fallback when ARI is unavailable: renew once
	// less than this fraction of the certificate lifetime remains.
	RenewRemaining float64 `yaml:"renew_remaining"`
	// WarnRemaining logs an expiry warning once less than this fraction
	// of the lifetime remains.
	WarnRemaining float64 `yaml:"warn_remaining"`
	// MaxIssuesPerWeek caps automatic (non-forced) issuance per certificate,
	// to stay clear of the CA's duplicate-certificate rate limit.
	MaxIssuesPerWeek int      `yaml:"max_issues_per_week"`
	RetryMin         Duration `yaml:"retry_min"`
	RetryMax         Duration `yaml:"retry_max"`
	KeepVersions     int      `yaml:"keep_versions"`
}

type SSH struct {
	User           string   `yaml:"user"`
	Port           int      `yaml:"port"`
	KeyFile        string   `yaml:"key_file"`
	KnownHostsFile string   `yaml:"known_hosts_file"`
	ConnectTimeout Duration `yaml:"connect_timeout"`
	// Parallel is the number of nodes pushed to concurrently.
	Parallel int `yaml:"parallel"`
}

// Partner configures the instructions printed by "onboard".
type Partner struct {
	Organization string `yaml:"organization"` // who is asking, e.g. "Example Corp"
	Contact      string `yaml:"contact"`      // where partners should reply
	// CAAPin controls the CAA accounturi step: "optional" (offered as a
	// recommendation, the default), "required" or "off".
	CAAPin string `yaml:"caa_pin"`
	// CAName is how the CA is named in instructions (default derived
	// from dns.caa_identifiers, e.g. "Let's Encrypt").
	CAName string `yaml:"ca_name"`
}

type Cluster struct {
	Name string `yaml:"name"`
	// RemoteDir is the destination directory on each node. With rrsync on
	// the node it is relative to the rrsync root.
	RemoteDir string `yaml:"remote_dir"`
	// Addresses are the cluster's public (floating) IPs. Used only by the
	// onboarding check to verify partner A/AAAA records.
	Addresses []string `yaml:"addresses"`
	Nodes     []Node   `yaml:"nodes"`
}

type Node struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	User string `yaml:"user"`
}

type Certificate struct {
	Name     string   `yaml:"name"`
	Domains  []string `yaml:"domains"`
	Clusters []string `yaml:"clusters"`
	KeyType  string   `yaml:"key_type"`
	Profile  string   `yaml:"profile"`
	// DelegateLabels overrides the derived delegate label for a domain
	// (keyed by domain without any "*." prefix).
	DelegateLabels map[string]string `yaml:"delegate_labels"`
}

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	domainRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)
	keyTypes = map[string]bool{"ec256": true, "ec384": true, "rsa2048": true, "rsa3072": true, "rsa4096": true}
)

// Load reads the config file named by the environment (or path, if non-empty)
// and resolves secrets from the environment.
func Load(path string) (*Config, error) {
	if path == "" {
		path = envOr(EnvConfig, DefaultConfigPath)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sshKey []byte
	if v := os.Getenv(EnvSSHKey); v != "" {
		if sshKey, err = decodeSSHKey(v); err != nil {
			return nil, err
		}
	}
	cfg, err := parse(raw, sshKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.DataDir = envOr(EnvDataDir, DefaultDataDir)
	if cfg.sshKey != nil {
		cfg.SSH.KeyFile = filepath.Join(cfg.DataDir, "ssh_key")
	}
	return cfg, nil
}

// decodeSSHKey accepts a private key in PEM form, or base64-encoded (which
// survives env files that cannot carry newlines).
func decodeSSHKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "-----BEGIN ") {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), ""))
		if err != nil {
			return nil, fmt.Errorf("%s: neither a PEM private key nor base64: %w", EnvSSHKey, err)
		}
		v = strings.TrimSpace(string(b))
		if !strings.HasPrefix(v, "-----BEGIN ") {
			return nil, fmt.Errorf("%s: does not contain a PEM private key", EnvSSHKey)
		}
	}
	return []byte(v + "\n"), nil
}

// WriteSSHKey writes a key given in ACME_STEWARD_SSH_KEY to ssh.key_file
// (in the data directory, mode 0600) for ssh to read. It does nothing when
// the key comes from a file named in the configuration.
func (c *Config) WriteSSHKey() error {
	if c.sshKey == nil {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(c.SSH.KeyFile), ".ssh_key.*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(c.sshKey); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), c.SSH.KeyFile)
}

// DOToken returns the DigitalOcean token from DO_AUTH_TOKEN or the file
// named by DO_AUTH_TOKEN_FILE. Only commands that talk to DigitalOcean need it.
func DOToken() (string, error) {
	if f := os.Getenv(EnvDOAuthTokenFile); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s: %w", EnvDOAuthTokenFile, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := os.Getenv(EnvDOAuthToken); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%s or %s must be set", EnvDOAuthToken, EnvDOAuthTokenFile)
}

// Parse parses and validates config file content, applying defaults.
func Parse(raw []byte) (*Config, error) { return parse(raw, nil) }

func parse(raw []byte, sshKey []byte) (*Config, error) {
	cfg := &Config{sshKey: sshKey}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	setDefault(&c.ACME.CA, "letsencrypt-staging")
	setDefault(&c.ACME.KeyType, "ec256")
	if len(c.DNS.Resolvers) == 0 {
		c.DNS.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	for i, r := range c.DNS.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			c.DNS.Resolvers[i] = net.JoinHostPort(r, "53")
		}
	}
	if c.DNS.PropagationTimeout == 0 {
		c.DNS.PropagationTimeout = Duration(5 * time.Minute)
	}
	if c.DNS.PropagationSettle == nil {
		d := Duration(90 * time.Second)
		c.DNS.PropagationSettle = &d
	}
	if c.DNS.TTL == 0 {
		c.DNS.TTL = 30
	}
	if len(c.DNS.CAAIdentifiers) == 0 {
		c.DNS.CAAIdentifiers = []string{"letsencrypt.org"}
	}
	c.DNS.DelegateZone = normDomain(c.DNS.DelegateZone)
	setDefault(&c.Partner.CAAPin, "optional")
	if c.Partner.CAName == "" {
		c.Partner.CAName = c.DNS.CAAIdentifiers[0]
		if c.Partner.CAName == "letsencrypt.org" {
			c.Partner.CAName = "Let's Encrypt"
		}
	}

	r := &c.Renewal
	if r.CheckInterval == 0 {
		r.CheckInterval = Duration(time.Hour)
	}
	if r.RenewRemaining == 0 {
		r.RenewRemaining = 1.0 / 3
	}
	if r.WarnRemaining == 0 {
		r.WarnRemaining = 1.0 / 6
	}
	if r.MaxIssuesPerWeek == 0 {
		r.MaxIssuesPerWeek = 3
	}
	if r.RetryMin == 0 {
		r.RetryMin = Duration(time.Hour)
	}
	if r.RetryMax == 0 {
		r.RetryMax = Duration(24 * time.Hour)
	}
	if r.KeepVersions == 0 {
		r.KeepVersions = 3
	}

	s := &c.SSH
	if s.Port == 0 {
		s.Port = 22
	}
	if s.ConnectTimeout == 0 {
		s.ConnectTimeout = Duration(15 * time.Second)
	}
	if s.Parallel == 0 {
		s.Parallel = 4
	}

	for i := range c.Clusters {
		cl := &c.Clusters[i]
		for j := range cl.Nodes {
			n := &cl.Nodes[j]
			if n.Port == 0 {
				n.Port = s.Port
			}
			setDefault(&n.User, s.User)
		}
	}
	for i := range c.Certificates {
		ct := &c.Certificates[i]
		setDefault(&ct.KeyType, c.ACME.KeyType)
		setDefault(&ct.Profile, c.ACME.Profile)
		for j, d := range ct.Domains {
			ct.Domains[j] = normDomain(d)
		}
	}
}

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if u, ok := caDirectories[c.ACME.CA]; ok {
		c.CADirectory = u
	} else if strings.HasPrefix(c.ACME.CA, "https://") {
		c.CADirectory = c.ACME.CA
	} else {
		fail("acme.ca must be letsencrypt, letsencrypt-staging or an https:// directory URL")
	}
	if !keyTypes[c.ACME.KeyType] {
		fail("acme.key_type %q is not supported", c.ACME.KeyType)
	}
	if c.DNS.DelegateZone == "" || !domainRE.MatchString(c.DNS.DelegateZone) {
		fail("dns.delegate_zone must be a domain name")
	}
	switch c.Partner.CAAPin {
	case "optional", "required", "off":
	default:
		fail("partner_instructions.caa_pin must be optional, required or off")
	}
	if c.Renewal.RenewRemaining <= 0 || c.Renewal.RenewRemaining >= 1 {
		fail("renewal.renew_remaining must be between 0 and 1")
	}
	if c.Renewal.WarnRemaining <= 0 || c.Renewal.WarnRemaining >= c.Renewal.RenewRemaining {
		fail("renewal.warn_remaining must be between 0 and renewal.renew_remaining")
	}
	if c.sshKey != nil && c.SSH.KeyFile != "" {
		fail("ssh.key_file and %s are mutually exclusive", EnvSSHKey)
	}
	if len(c.Clusters) > 0 && c.SSH.KeyFile == "" && c.sshKey == nil {
		fail("ssh.key_file (or %s) is required", EnvSSHKey)
	}
	if len(c.Clusters) > 0 && c.SSH.KnownHostsFile == "" {
		fail("ssh.known_hosts_file is required (host keys are always verified)")
	}

	c.clusterByName = map[string]*Cluster{}
	for i := range c.Clusters {
		cl := &c.Clusters[i]
		if !nameRE.MatchString(cl.Name) {
			fail("cluster name %q is invalid", cl.Name)
		}
		if c.clusterByName[cl.Name] != nil {
			fail("duplicate cluster %q", cl.Name)
		}
		c.clusterByName[cl.Name] = cl
		if cl.RemoteDir == "" {
			fail("cluster %s: remote_dir is required", cl.Name)
		}
		if len(cl.Nodes) == 0 {
			fail("cluster %s: no nodes", cl.Name)
		}
		for _, n := range cl.Nodes {
			if n.Host == "" || strings.HasPrefix(n.Host, "-") {
				fail("cluster %s: invalid node host %q", cl.Name, n.Host)
			}
			if n.User == "" {
				fail("cluster %s: node %s has no user (set ssh.user or node user)", cl.Name, n.Host)
			}
		}
	}

	certNames := map[string]bool{}
	domainOwner := map[string]string{}
	for _, ct := range c.Certificates {
		if !nameRE.MatchString(ct.Name) || ct.Name == "." || ct.Name == ".." {
			fail("certificate name %q is invalid", ct.Name)
		}
		if certNames[ct.Name] {
			fail("duplicate certificate %q", ct.Name)
		}
		certNames[ct.Name] = true
		if len(ct.Domains) == 0 {
			fail("certificate %s: no domains", ct.Name)
		}
		for _, d := range ct.Domains {
			if !domainRE.MatchString(d) {
				fail("certificate %s: invalid domain %q", ct.Name, d)
			}
			if o, dup := domainOwner[d]; dup {
				fail("domain %s appears in certificates %s and %s", d, o, ct.Name)
			}
			domainOwner[d] = ct.Name
		}
		if !keyTypes[ct.KeyType] {
			fail("certificate %s: key_type %q is not supported", ct.Name, ct.KeyType)
		}
		for _, cn := range ct.Clusters {
			if c.clusterByName[cn] == nil {
				fail("certificate %s: unknown cluster %q", ct.Name, cn)
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Config) Cluster(name string) *Cluster { return c.clusterByName[name] }

// Cert returns the certificate with the given name, or nil.
func (c *Config) Cert(name string) *Certificate {
	for i := range c.Certificates {
		if c.Certificates[i].Name == name {
			return &c.Certificates[i]
		}
	}
	return nil
}

// CertForDomain returns the certificate containing the given domain, or nil.
func (c *Config) CertForDomain(domain string) *Certificate {
	domain = normDomain(domain)
	for i := range c.Certificates {
		for _, d := range c.Certificates[i].Domains {
			if d == domain {
				return &c.Certificates[i]
			}
		}
	}
	return nil
}

// CertsForCluster returns the certificates pushed to the named cluster.
func (c *Config) CertsForCluster(name string) []*Certificate {
	var out []*Certificate
	for i := range c.Certificates {
		for _, cn := range c.Certificates[i].Clusters {
			if cn == name {
				out = append(out, &c.Certificates[i])
			}
		}
	}
	return out
}

func normDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
