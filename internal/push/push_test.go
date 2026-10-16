package push

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/testutil"
)

func TestArgs(t *testing.T) {
	p := New(config.SSH{KeyFile: "/k ey", KnownHostsFile: "/kh", ConnectTimeout: config.Duration(15e9)}, "/data/certs")
	a1, a2 := p.Args(config.Node{Host: "2001:db8::1", Port: 2222, User: "u"}, "certs/", []string{"a", "b"})
	if a1[len(a1)-1] != "u@[2001:db8::1]:certs/" {
		t.Error("destination", a1[len(a1)-1])
	}
	if !slices.Contains(a1, "--exclude=/*/current") || slices.Contains(a1, "--delete") {
		t.Error("phase 1 must exclude current and not delete", a1)
	}
	if slices.Contains(a2, "--exclude=/*/current") || !slices.Contains(a2, "--delete") {
		t.Error("phase 2 must include current and delete", a2)
	}
	e := a1[slices.Index(a1, "-e")+1]
	for _, want := range []string{"-p 2222", "-i '/k ey'", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/kh", "BatchMode=yes", "ConnectTimeout=15"} {
		if !strings.Contains(e, want) {
			t.Errorf("ssh command missing %q: %s", want, e)
		}
	}
	if !slices.Contains(a1, "/data/certs/a") || !slices.Contains(a1, "/data/certs/b") {
		t.Error("sources", a1)
	}
}

func TestPushNode(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed")
	}
	local, remote := t.TempDir(), t.TempDir()
	mk := func(p, content string) {
		os.MkdirAll(filepath.Dir(filepath.Join(local, p)), 0o750)
		os.WriteFile(filepath.Join(local, p), []byte(content), 0o640)
	}
	mk("a/v1/cert.pem", "one")
	os.Symlink("v1", filepath.Join(local, "a", "current"))

	p := New(config.SSH{}, local)
	p.SSHCommand = testutil.FakeSSH(t, filepath.Join(t.TempDir(), "nofail"))
	n := config.Node{Host: "h", User: "u"}
	ctx := context.Background()

	changed, err := p.PushNode(ctx, n, remote, []string{"a"})
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	if b, _ := os.ReadFile(filepath.Join(remote, "a", "current", "cert.pem")); string(b) != "one" {
		t.Fatal("remote content", string(b))
	}
	if changed, err = p.PushNode(ctx, n, remote, []string{"a"}); err != nil || changed {
		t.Fatal("second push should be a no-op", changed, err)
	}

	// New version; old one pruned locally.
	mk("a/v2/cert.pem", "two")
	os.Remove(filepath.Join(local, "a", "current"))
	os.Symlink("v2", filepath.Join(local, "a", "current"))
	os.RemoveAll(filepath.Join(local, "a", "v1"))
	if _, err := p.PushNode(ctx, n, remote, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(remote, "a", "current", "cert.pem")); string(b) != "two" {
		t.Fatal("remote content after update", string(b))
	}
	if _, err := os.Stat(filepath.Join(remote, "a", "v1")); !os.IsNotExist(err) {
		t.Error("pruned version not deleted remotely")
	}
	// Unrelated content in remote_dir is left alone.
	os.MkdirAll(filepath.Join(remote, "other"), 0o755)
	p.PushNode(ctx, n, remote, []string{"a"})
	if _, err := os.Stat(filepath.Join(remote, "other")); err != nil {
		t.Error("unrelated remote directory removed")
	}
}

func TestPushNodeFailure(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed")
	}
	fail := filepath.Join(t.TempDir(), "fail")
	os.WriteFile(fail, nil, 0o600)
	local := t.TempDir()
	os.MkdirAll(filepath.Join(local, "a"), 0o750)
	p := New(config.SSH{}, local)
	p.SSHCommand = testutil.FakeSSH(t, fail)
	_, err := p.PushNode(context.Background(), config.Node{Host: "h", User: "u"}, t.TempDir(), []string{"a"})
	if err == nil || !strings.Contains(err.Error(), "Connection refused") {
		t.Fatal("expected connection error, got", err)
	}
}
