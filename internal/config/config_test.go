package config

import (
	"os"
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
