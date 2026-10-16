package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// FakeSSH writes a script usable as rsync's -e command that runs the
// "remote" rsync locally, so pushes can be tested without sshd. If
// failFile exists when the script runs, it fails like an unreachable host.
func FakeSSH(t *testing.T, failFile string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fakessh")
	script := `#!/bin/sh
if [ -e '` + failFile + `' ]; then echo "ssh: connect to host: Connection refused" >&2; exit 255; fi
while [ "$1" != "rsync" ]; do shift; done
exec "$@"
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}
