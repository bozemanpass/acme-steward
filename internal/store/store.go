// Package store manages acme-steward's data directory:
//
//	<data>/lock                         single-instance lock
//	<data>/heartbeat                    time of the last completed cycle
//	<data>/account/account.key          ACME account private key
//	<data>/account/account.json         ACME account registration
//	<data>/certs/<name>/<version>/      cert.pem chain.pem fullchain.pem privkey.pem manifest.json
//	<data>/certs/<name>/current         symlink -> <version>
//	<data>/state/certs/<name>.json      renewal state (not pushed)
//	<data>/state/push.json              per-node push state (not pushed)
//
// certs/<name> is exactly what is mirrored to nodes.
package store

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	FileCert      = "cert.pem"
	FileChain     = "chain.pem"
	FileFullchain = "fullchain.pem"
	FileKey       = "privkey.pem"
	FileManifest  = "manifest.json"
	CurrentLink   = "current"
)

type Store struct {
	Root string
}

func New(root string) (*Store, error) {
	s := &Store{Root: root}
	for _, d := range []string{root, s.path("account"), s.path("certs"), s.path("state", "certs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// The root is the security boundary; everything below may be group
	// readable so that files keep sensible modes when mirrored to nodes.
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path(p ...string) string { return filepath.Join(append([]string{s.Root}, p...)...) }

// Lock takes an exclusive, non-blocking lock so only one instance runs
// against a data directory. The lock is released when the process exits.
func (s *Store) Lock() (func(), error) {
	f, err := os.OpenFile(s.path("lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another acme-steward instance holds %s", f.Name())
	}
	return func() { f.Close() }, nil
}

// --- account ---

func (s *Store) AccountKeyPath() string  { return s.path("account", "account.key") }
func (s *Store) AccountJSONPath() string { return s.path("account", "account.json") }

// --- certificates ---

// CertDir is the directory mirrored to nodes for a certificate.
func (s *Store) CertDir(name string) string { return s.path("certs", name) }

// Manifest describes one issued certificate version. It is pushed with the
// PEM files so node-side tooling can verify what it received.
type Manifest struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Domains   []string          `json:"domains"`
	Serial    string            `json:"serial"`
	Issuer    string            `json:"issuer"`
	NotBefore time.Time         `json:"not_before"`
	NotAfter  time.Time         `json:"not_after"`
	KeyType   string            `json:"key_type"`
	Profile   string            `json:"profile,omitempty"`
	CertURL   string            `json:"cert_url,omitempty"`
	Issued    time.Time         `json:"issued"`
	SHA256    map[string]string `json:"sha256"`
}

// Lifetime is the certificate's validity period.
func (m *Manifest) Lifetime() time.Duration { return m.NotAfter.Sub(m.NotBefore) }

// Bundle is a newly issued certificate to be saved.
type Bundle struct {
	Name, KeyType, Profile, CertURL string
	Domains                         []string
	Key, Cert, Chain                []byte // PEM
}

// Save writes a new version and atomically points current at it.
func (s *Store) Save(b Bundle, now time.Time) (*Manifest, error) {
	leaf, err := ParseLeaf(b.Cert)
	if err != nil {
		return nil, err
	}
	serial := leaf.SerialNumber.Text(16)
	version := now.UTC().Format("20060102T150405.000Z") + "-" + serial[:min(len(serial), 12)]
	dir := s.CertDir(b.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(dir, ".tmp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o750); err != nil {
		return nil, err
	}

	fullchain := append(append([]byte{}, b.Cert...), b.Chain...)
	files := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{FileCert, b.Cert, 0o640},
		{FileChain, b.Chain, 0o640},
		{FileFullchain, fullchain, 0o640},
		{FileKey, b.Key, 0o600},
	}
	m := &Manifest{
		Name: b.Name, Version: version, Domains: b.Domains, Serial: serial,
		Issuer: leaf.Issuer.CommonName, NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(),
		KeyType: b.KeyType, Profile: b.Profile, CertURL: b.CertURL, Issued: now.UTC(),
		SHA256: map[string]string{},
	}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		m.SHA256[f.name] = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(tmp, f.name), f.data, f.mode); err != nil {
			return nil, err
		}
	}
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, FileManifest), append(mj, '\n'), 0o640); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, version)); err != nil {
		return nil, err
	}
	// Atomic symlink swap.
	link := filepath.Join(dir, CurrentLink)
	tmpLink := link + ".tmp"
	os.Remove(tmpLink)
	if err := os.Symlink(version, tmpLink); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpLink, link); err != nil {
		return nil, err
	}
	return m, nil
}

// Current returns the manifest of the current version, or nil if none.
func (s *Store) Current(name string) (*Manifest, error) {
	dir := s.CertDir(name)
	v, err := os.Readlink(filepath.Join(dir, CurrentLink))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return readJSON[Manifest](filepath.Join(dir, v, FileManifest))
}

// CurrentLeaf parses the current version's leaf certificate.
func (s *Store) CurrentLeaf(name string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(s.CertDir(name), CurrentLink, FileCert))
	if err != nil {
		return nil, err
	}
	return ParseLeaf(b)
}

// Prune removes all but the newest keep versions (never the current one).
func (s *Store) Prune(name string, keep int) ([]string, error) {
	dir := s.CertDir(name)
	cur, _ := os.Readlink(filepath.Join(dir, CurrentLink))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			versions = append(versions, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	var removed []string
	for i, v := range versions {
		if i < keep || v == cur {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, v)); err != nil {
			return removed, err
		}
		removed = append(removed, v)
	}
	return removed, nil
}

// --- renewal state ---

type CertState struct {
	// Issued records automatic and forced issuance times (last 7 days are
	// used for the rate guard).
	Issued       []time.Time `json:"issued,omitempty"`
	Failures     int         `json:"failures,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
	LastAttempt  time.Time   `json:"last_attempt,omitzero"`
	NextAttempt  time.Time   `json:"next_attempt,omitzero"`
	RenewAt      time.Time   `json:"renew_at,omitzero"`         // from ARI or fallback
	RenewAtFrom  string      `json:"renew_at_source,omitempty"` // "ari" or "lifetime"
	RenewAtFor   string      `json:"renew_at_for,omitempty"`    // version RenewAt was computed for
	ARICheckedAt time.Time   `json:"ari_checked_at,omitzero"`
	ARINextCheck time.Time   `json:"ari_next_check,omitzero"`
}

func (s *Store) CertState(name string) (*CertState, error) {
	st, err := readJSON[CertState](s.path("state", "certs", name+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return &CertState{}, nil
	}
	return st, err
}

func (s *Store) SaveCertState(name string, st *CertState) error {
	return writeJSON(s.path("state", "certs", name+".json"), st)
}

// --- push state ---

type NodePush struct {
	Version     string    `json:"version,omitempty"` // last version confirmed delivered
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures,omitempty"`
}

// PushState maps "cluster/host" -> cert name -> state.
type PushState map[string]map[string]*NodePush

func (s *Store) PushState() (PushState, error) {
	ps, err := readJSON[PushState](s.path("state", "push.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return PushState{}, nil
	}
	if err != nil {
		return nil, err
	}
	return *ps, nil
}

func (s *Store) SavePushState(ps PushState) error { return writeJSON(s.path("state", "push.json"), ps) }

// --- heartbeat ---

func (s *Store) Heartbeat(now time.Time) error {
	return writeFileAtomic(s.path("heartbeat"), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func (s *Store) LastHeartbeat() (time.Time, error) {
	b, err := os.ReadFile(s.path("heartbeat"))
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
}

// --- helpers ---

// ParseLeaf returns the first certificate in PEM data.
func ParseLeaf(pemData []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, pemData = pem.Decode(pemData)
		if blk == nil {
			return nil, errors.New("no certificate found in PEM data")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func readJSON[T any](path string) (*T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v := new(T)
	if err := json.Unmarshal(b, v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteFileAtomic is exported for the account files.
func WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	return writeFileAtomic(path, data, mode)
}
