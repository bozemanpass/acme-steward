// Package push mirrors certificate directories to cluster nodes with rsync
// over ssh.
//
// Each push is two rsync runs, so a node never sees "current" pointing at a
// version whose files have not fully arrived:
//
//  1. copy every version directory, excluding the "current" symlinks;
//  2. copy again with --delete, which updates "current" and removes
//     versions that have been pruned locally.
package push

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bozemanpass/acme-steward/internal/config"
)

type Pusher struct {
	SSH config.SSH
	// CertsDir is the local directory containing one subdirectory per certificate.
	CertsDir string
	// RsyncPath and SSHCommand may be overridden (tests).
	RsyncPath  string
	SSHCommand string
	Timeout    time.Duration
}

func New(ssh config.SSH, certsDir string) *Pusher {
	return &Pusher{SSH: ssh, CertsDir: certsDir, RsyncPath: "rsync", Timeout: 5 * time.Minute}
}

// sshCommand is passed to rsync -e. Host keys are always verified against
// the configured known_hosts file and the user's ssh config is ignored.
func (p *Pusher) sshCommand(n config.Node) string {
	if p.SSHCommand != "" {
		return p.SSHCommand
	}
	args := []string{
		"ssh", "-F", "none",
		"-p", fmt.Sprint(n.Port),
		"-i", shellQuote(p.SSH.KeyFile),
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + shellQuote(p.SSH.KnownHostsFile),
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(p.SSH.ConnectTimeout.D().Seconds())),
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
	}
	return strings.Join(args, " ")
}

func destination(n config.Node, remoteDir string) string {
	host := n.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s@%s:%s/", n.User, host, strings.TrimSuffix(remoteDir, "/"))
}

// Args returns the rsync arguments for the two phases.
func (p *Pusher) Args(n config.Node, remoteDir string, certs []string) (phase1, phase2 []string) {
	common := []string{
		"--recursive", "--links", "--perms", "--times",
		"--itemize-changes", "--timeout=60",
		"--exclude=/*/.tmp-*", "--exclude=/*/current.tmp",
		"-e", p.sshCommand(n),
	}
	var srcs []string
	for _, c := range certs {
		// No trailing slash: each certificate lands in <remote_dir>/<name>.
		srcs = append(srcs, filepath.Join(p.CertsDir, c))
	}
	dst := destination(n, remoteDir)
	phase1 = append(append(append([]string{}, common...), "--exclude=/*/current"), srcs...)
	phase1 = append(phase1, dst)
	phase2 = append(append(append([]string{}, common...), "--delete"), srcs...)
	phase2 = append(phase2, dst)
	return phase1, phase2
}

// PushNode mirrors the given certificates to one node. changed reports
// whether anything was transferred or deleted.
func (p *Pusher) PushNode(ctx context.Context, n config.Node, remoteDir string, certs []string) (changed bool, err error) {
	if len(certs) == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	a1, a2 := p.Args(n, remoteDir, certs)
	for _, args := range [][]string{a1, a2} {
		out, err := p.run(ctx, args)
		if err != nil {
			return changed, err
		}
		if strings.TrimSpace(out) != "" {
			changed = true
		}
	}
	return changed, nil
}

func (p *Pusher) run(ctx context.Context, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, p.RsyncPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = "..." + msg[len(msg)-500:]
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("rsync timed out: %s", msg)
		}
		return "", fmt.Errorf("rsync: %v: %s", err, msg)
	}
	return stdout.String(), nil
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
