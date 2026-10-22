package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleConfig(t *testing.T) {
	raw, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.CADirectory != caDirectories["letsencrypt-staging"] {
		t.Error("CA directory", c.CADirectory)
	}
	if c.DNS.Resolvers[0] != "1.1.1.1:53" {
		t.Error("resolver port not defaulted:", c.DNS.Resolvers)
	}
	n := c.Cluster("east").Nodes
	if n[0].User != "certdeploy" || n[0].Port != 22 || n[2].Port != 2222 {
		t.Errorf("node defaults: %+v", n)
	}
	b := c.Cert("partner-b")
	if b.KeyType != "rsa2048" || b.Domains[0] != "*.svc.partner-b.example.org" {
		t.Errorf("cert: %+v", b)
	}
	if c.CertForDomain("SYNC.partner-a.example.com.").Name != "partner-a" {
		t.Error("CertForDomain")
	}
	if len(c.CertsForCluster("east")) != 2 {
		t.Error("CertsForCluster")
	}
}

func TestValidation(t *testing.T) {
	bad := `
acme: {ca: nope, key_type: dsa}
dns: {delegate_zone: ""}
ssh: {}
clusters:
  - {name: c, nodes: [{host: "-oProxyCommand=x"}]}
  - {name: c, remote_dir: x, nodes: [{host: h, user: u}]}
certificates:
  - {name: a, domains: [x.example.com], clusters: [missing]}
  - {name: a, domains: [x.example.com, "bad domain"]}
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"acme.ca", "key_type", "delegate_zone", "ssh.key_file", "known_hosts",
		"duplicate cluster", "remote_dir", "invalid node host", "unknown cluster", "duplicate certificate",
		"appears in certificates", "invalid domain"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing error %q in:\n%v", want, err)
		}
	}
	if _, err := Parse([]byte("acme: {bogus: 1}")); err == nil {
		t.Error("unknown fields must be rejected")
	}
	// No default CA: staging certificates would otherwise be delivered by accident
	if _, err := Parse([]byte("dns: {delegate_zone: d.example.net}")); err == nil || !strings.Contains(err.Error(), "acme.ca is required") {
		t.Errorf("a missing acme.ca must be rejected, got: %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	if d, _ := ParseDuration("14d"); d != 14*24*time.Hour {
		t.Error(d)
	}
	if d, _ := ParseDuration("90m"); d != 90*time.Minute {
		t.Error(d)
	}
	if _, err := ParseDuration("x"); err == nil {
		t.Error("expected error")
	}
}

func TestSSHKeyFromEnv(t *testing.T) {
	raw, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	withKey := strings.Replace(string(raw), "  key_file: /run/secrets/acme-steward/ssh_key\n", "", 1)
	if withKey == string(raw) {
		t.Fatal("example config has no ssh.key_file line to remove")
	}
	if _, err := Parse([]byte(withKey)); err == nil || !strings.Contains(err.Error(), "ssh.key_file") {
		t.Fatalf("missing key must be rejected, got %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(withKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDataDir, dir)
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
	for name, v := range map[string]string{
		"pem":    pem,
		"base64": base64.StdEncoding.EncodeToString([]byte(pem + "\n")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvSSHKey, v)
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if c.SSH.KeyFile != filepath.Join(dir, "ssh_key") {
				t.Fatal("key file", c.SSH.KeyFile)
			}
			if err := c.WriteSSHKey(); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(c.SSH.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("mode %v", fi.Mode().Perm())
			}
			if b, _ := os.ReadFile(c.SSH.KeyFile); string(b) != pem+"\n" {
				t.Errorf("content %q", b)
			}
		})
	}

	t.Setenv(EnvSSHKey, "not a key")
	if _, err := Load(path); err == nil {
		t.Error("garbage key must be rejected")
	}
	t.Setenv(EnvSSHKey, pem)
	both := filepath.Join(dir, "both.yaml")
	if err := os.WriteFile(both, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(both); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("key_file and %s together must be rejected, got %v", EnvSSHKey, err)
	}
}
