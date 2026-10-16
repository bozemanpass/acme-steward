package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bozemanpass/acme-steward/internal/testutil"
)

func TestSaveCurrentPrune(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if m, err := s.Current("a"); m != nil || err != nil {
		t.Fatal("expected no current", m, err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var versions []string
	for i := range 5 {
		cert, key, chain := testutil.Cert([]string{"a.example.com"}, now, now.Add(90*24*time.Hour))
		m, err := s.Save(Bundle{Name: "a", Domains: []string{"a.example.com"}, KeyType: "ec256",
			Key: key, Cert: cert, Chain: chain}, now.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, m.Version)
	}
	cur, err := s.Current("a")
	if err != nil || cur.Version != versions[4] {
		t.Fatal("current", cur, err)
	}
	if cur.Lifetime() != 90*24*time.Hour {
		t.Error("lifetime", cur.Lifetime())
	}
	fi, _ := os.Stat(filepath.Join(s.CertDir("a"), "current", FileKey))
	if fi.Mode().Perm() != 0o600 {
		t.Error("key mode", fi.Mode())
	}
	full, _ := os.ReadFile(filepath.Join(s.CertDir("a"), "current", FileFullchain))
	if leaf, err := ParseLeaf(full); err != nil || leaf.SerialNumber.Text(16) != cur.Serial {
		t.Error("fullchain leaf", err)
	}
	removed, err := s.Prune("a", 3)
	if err != nil || len(removed) != 2 || removed[0] != versions[1] {
		t.Fatal("prune", removed, err)
	}
	if _, err := os.Stat(filepath.Join(s.CertDir("a"), versions[0])); !os.IsNotExist(err) {
		t.Error("oldest version not removed")
	}
}

func TestStateAndLock(t *testing.T) {
	s, _ := New(t.TempDir())
	st, _ := s.CertState("x")
	st.Failures = 2
	if err := s.SaveCertState("x", st); err != nil {
		t.Fatal(err)
	}
	if st2, _ := s.CertState("x"); st2.Failures != 2 {
		t.Error("state round trip")
	}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil {
		t.Error("second lock should fail")
	}
	unlock()
	if u, err := s.Lock(); err != nil {
		t.Error("relock", err)
	} else {
		u()
	}
}
