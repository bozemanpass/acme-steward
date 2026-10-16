// Package steward ties issuance, renewal scheduling and distribution together.
package steward

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/issuer"
	"github.com/bozemanpass/acme-steward/internal/label"
	"github.com/bozemanpass/acme-steward/internal/push"
	"github.com/bozemanpass/acme-steward/internal/store"
)

// Issuer is the subset of *issuer.Issuer the steward uses.
type Issuer interface {
	Obtain(ct *config.Certificate, replacing *x509.Certificate) (*store.Bundle, error)
	RenewalInfo(leaf *x509.Certificate) (*RenewalInfo, error)
	AccountURI() string
}

// RenewalInfo is the ARI suggested window.
type RenewalInfo struct {
	Start, End time.Time
	RetryAfter time.Duration
}

type Steward struct {
	Cfg   *config.Config
	Store *store.Store
	Log   *slog.Logger
	// NewIssuer creates the issuer on first use, so that commands and
	// cycles that need no CA access never contact it.
	NewIssuer func() (Issuer, error)
	Pusher    *push.Pusher
	Now       func() time.Time

	issuer Issuer
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger, doToken string) *Steward {
	s := &Steward{
		Cfg: cfg, Store: st, Log: log,
		Pusher: push.New(cfg.SSH, st.CertDir("")),
		Now:    time.Now,
	}
	s.NewIssuer = func() (Issuer, error) {
		iss, err := issuer.New(cfg, st, doToken, log)
		if err != nil {
			return nil, err
		}
		return legoIssuer{iss}, nil
	}
	return s
}

type legoIssuer struct{ *issuer.Issuer }

func (l legoIssuer) RenewalInfo(leaf *x509.Certificate) (*RenewalInfo, error) {
	ri, err := l.Issuer.RenewalInfo(leaf)
	if err != nil || ri == nil {
		return nil, err
	}
	return &RenewalInfo{Start: ri.SuggestedWindow.Start, End: ri.SuggestedWindow.End, RetryAfter: ri.RetryAfter}, nil
}

func (s *Steward) Issuer() (Issuer, error) {
	if s.issuer == nil {
		iss, err := s.NewIssuer()
		if err != nil {
			return nil, err
		}
		s.issuer = iss
	}
	return s.issuer, nil
}

// DelegateLabel is the delegate-zone label for one of a certificate's domains.
func DelegateLabel(ct *config.Certificate, domain string) string {
	base := label.BaseDomain(domain)
	if l := ct.DelegateLabels[base]; l != "" {
		return l
	}
	return label.Derive(base)
}

// Run cycles until ctx is cancelled.
func (s *Steward) Run(ctx context.Context) error {
	s.Log.Info("starting", "event", "steward.start", "certificates", len(s.Cfg.Certificates),
		"clusters", len(s.Cfg.Clusters), "ca", s.Cfg.CADirectory, "interval", s.Cfg.Renewal.CheckInterval.D().String())
	// The first cycle may take a while (initial issuance), so count startup
	// as a heartbeat.
	_ = s.Store.Heartbeat(s.Now())
	for {
		s.Cycle(ctx)
		// Jitter avoids synchronised load on the CA across deployments.
		interval := s.Cfg.Renewal.CheckInterval.D()
		wait := interval + time.Duration(rand.Int64N(int64(interval/10)+1))
		select {
		case <-ctx.Done():
			s.Log.Info("stopping", "event", "steward.stop")
			return nil
		case <-time.After(wait):
		}
	}
}

// Cycle renews whatever is due, reconciles every node, and checks expiry.
func (s *Steward) Cycle(ctx context.Context) {
	start := s.Now()
	s.RenewAll(ctx, nil, false)
	if ctx.Err() != nil {
		return
	}
	s.PushAll(ctx, nil)
	s.CheckExpiry()
	if err := s.Store.Heartbeat(s.Now()); err != nil {
		s.Log.Error("writing heartbeat", "event", "steward.error", "error", err)
	}
	s.Log.Debug("cycle complete", "event", "steward.cycle", "duration", s.Now().Sub(start).String())
}

// --- renewal ---

// RenewAll renews the named certificates (all if names is empty) when due,
// or unconditionally if force is set. It returns the number of failures.
func (s *Steward) RenewAll(ctx context.Context, names []string, force bool) int {
	failed := 0
	for i := range s.Cfg.Certificates {
		ct := &s.Cfg.Certificates[i]
		if len(names) > 0 && !slices.Contains(names, ct.Name) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		if err := s.renewOne(ct, force); err != nil {
			failed++
		}
	}
	return failed
}

func (s *Steward) renewOne(ct *config.Certificate, force bool) error {
	log := s.Log.With("cert", ct.Name)
	now := s.Now()
	st, err := s.Store.CertState(ct.Name)
	if err != nil {
		log.Error("reading state", "event", "cert.error", "error", err)
		return err
	}
	cur, err := s.Store.Current(ct.Name)
	if err != nil {
		log.Error("reading current certificate", "event", "cert.error", "error", err)
		return err
	}

	reason := "forced"
	if !force {
		reason = s.renewReason(ct, cur, st, log)
		if err := s.Store.SaveCertState(ct.Name, st); err != nil {
			log.Error("saving state", "event", "cert.error", "error", err)
		}
		if reason == "" {
			return nil
		}
		if now.Before(st.NextAttempt) {
			log.Debug("renewal due but backing off after failure", "event", "cert.backoff",
				"reason", reason, "next_attempt", st.NextAttempt, "failures", st.Failures)
			return nil
		}
		week := 0
		for _, t := range st.Issued {
			if now.Sub(t) < 7*24*time.Hour {
				week++
			}
		}
		if week >= s.Cfg.Renewal.MaxIssuesPerWeek {
			log.Error("renewal due but issuance guard reached; use renew --force to override",
				"event", "cert.rate_guard", "reason", reason, "issued_last_week", week)
			return errors.New("rate guard")
		}
	}

	log.Info("requesting certificate", "event", "cert.issuing", "reason", reason, "domains", ct.Domains)
	st.LastAttempt = now
	m, err := s.issue(ct, cur)
	if err != nil {
		st.Failures++
		st.LastError = err.Error()
		backoff := s.Cfg.Renewal.RetryMin.D() << min(st.Failures-1, 16)
		st.NextAttempt = now.Add(min(backoff, s.Cfg.Renewal.RetryMax.D()))
		log.Error("certificate request failed", "event", "cert.issue_failed", "error", err,
			"failures", st.Failures, "next_attempt", st.NextAttempt)
		_ = s.Store.SaveCertState(ct.Name, st)
		return err
	}
	st.Failures, st.LastError, st.NextAttempt = 0, "", time.Time{}
	st.RenewAt, st.RenewAtFrom, st.RenewAtFor = time.Time{}, "", ""
	st.ARINextCheck = time.Time{}
	st.Issued = append(slices.DeleteFunc(st.Issued, func(t time.Time) bool { return now.Sub(t) > 7*24*time.Hour }), now)
	if err := s.Store.SaveCertState(ct.Name, st); err != nil {
		log.Error("saving state", "event", "cert.error", "error", err)
	}
	log.Info("certificate issued", "event", "cert.issued", "version", m.Version, "serial", m.Serial,
		"not_after", m.NotAfter, "issuer", m.Issuer, "domains", m.Domains)
	if removed, err := s.Store.Prune(ct.Name, s.Cfg.Renewal.KeepVersions); err != nil {
		log.Warn("pruning old versions", "event", "cert.prune_failed", "error", err)
	} else if len(removed) > 0 {
		log.Info("pruned old versions", "event", "cert.pruned", "versions", removed)
	}
	return nil
}

func (s *Steward) issue(ct *config.Certificate, cur *store.Manifest) (*store.Manifest, error) {
	iss, err := s.Issuer()
	if err != nil {
		return nil, err
	}
	var replacing *x509.Certificate
	if cur != nil && sameSet(cur.Domains, ct.Domains) {
		replacing, _ = s.Store.CurrentLeaf(ct.Name)
	}
	b, err := iss.Obtain(ct, replacing)
	if err != nil {
		return nil, err
	}
	return s.Store.Save(*b, s.Now())
}

// renewReason returns why the certificate should be renewed now, or "".
// It updates the ARI-derived schedule in st.
func (s *Steward) renewReason(ct *config.Certificate, cur *store.Manifest, st *store.CertState, log *slog.Logger) string {
	now := s.Now()
	switch {
	case cur == nil:
		return "initial"
	case !sameSet(cur.Domains, ct.Domains):
		return "domains_changed"
	case cur.KeyType != ct.KeyType:
		return "key_type_changed"
	case cur.Profile != ct.Profile:
		return "profile_changed"
	case !now.Before(cur.NotAfter):
		return "expired"
	}

	if st.RenewAtFor != cur.Version || !now.Before(st.ARINextCheck) {
		s.schedule(ct, cur, st, log)
	}
	if !now.Before(st.RenewAt) {
		return "scheduled_" + st.RenewAtFrom
	}
	return ""
}

// schedule sets st.RenewAt from ARI, falling back to a fraction of lifetime.
func (s *Steward) schedule(ct *config.Certificate, cur *store.Manifest, st *store.CertState, log *slog.Logger) {
	now := s.Now()
	fallback := cur.NotAfter.Add(-time.Duration(float64(cur.Lifetime()) * s.Cfg.Renewal.RenewRemaining))
	renewAt, from := fallback, "lifetime"
	next := now.Add(6 * time.Hour)

	var ri *RenewalInfo
	var err error
	iss, err := s.Issuer()
	if err == nil {
		var leaf *x509.Certificate
		if leaf, err = s.Store.CurrentLeaf(ct.Name); err == nil {
			ri, err = iss.RenewalInfo(leaf)
		}
	}
	switch {
	case err != nil:
		log.Warn("ARI lookup failed; using lifetime-based schedule", "event", "cert.ari_failed", "error", err)
		next = now.Add(time.Hour)
	case ri != nil:
		// Keep the previously chosen point if the window hasn't moved, so
		// the random choice is stable across checks.
		if st.RenewAtFrom == "ari" && st.RenewAtFor == cur.Version &&
			!st.RenewAt.Before(ri.Start) && !st.RenewAt.After(ri.End) {
			renewAt = st.RenewAt
		} else {
			renewAt = ri.Start
			if w := ri.End.Sub(ri.Start); w > 0 {
				renewAt = renewAt.Add(time.Duration(rand.Int64N(int64(w))))
			}
		}
		from = "ari"
		if ri.RetryAfter > 0 {
			next = now.Add(min(max(ri.RetryAfter, time.Hour), 24*time.Hour))
		}
	}
	if renewAt != st.RenewAt || st.RenewAtFor != cur.Version {
		log.Info("renewal scheduled", "event", "cert.renewal_scheduled", "renew_at", renewAt,
			"source", from, "not_after", cur.NotAfter, "version", cur.Version)
	}
	st.RenewAt, st.RenewAtFrom, st.RenewAtFor = renewAt, from, cur.Version
	st.ARICheckedAt, st.ARINextCheck = now, next
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// --- distribution ---

// pushJob is one rsync destination: a host and remote directory, with the
// union of certificates its clusters carry there.
type pushJob struct {
	node      config.Node
	remoteDir string
	certs     []string
	// clusterCerts maps each "cluster/host" state key served by this job to
	// that cluster's certificates.
	clusterCerts map[string][]string
}

// PushAll reconciles every node of the named clusters (all if empty) with
// the current certificate versions. It returns the number of failed pushes.
//
// A host may belong to several clusters. Pushes to the same host run one
// at a time (rrsync on the node refuses concurrent sessions), and clusters
// sharing a remote directory on a host are merged into one push.
func (s *Steward) PushAll(ctx context.Context, clusters []string) int {
	ps, err := s.Store.PushState()
	if err != nil {
		s.Log.Error("reading push state", "event", "push.error", "error", err)
		ps = store.PushState{}
	}
	versions := map[string]string{}
	for _, ct := range s.Cfg.Certificates {
		m, err := s.Store.Current(ct.Name)
		if err != nil {
			s.Log.Error("reading current certificate", "event", "push.error", "cert", ct.Name, "error", err)
			continue
		}
		if m != nil {
			versions[ct.Name] = m.Version
		}
	}

	live := map[string]bool{}
	byHost := map[string][]*pushJob{} // user@host:port -> jobs, run sequentially
	var hosts []string
	for i := range s.Cfg.Clusters {
		cl := &s.Cfg.Clusters[i]
		selected := len(clusters) == 0 || slices.Contains(clusters, cl.Name)
		var names []string
		for _, ct := range s.Cfg.CertsForCluster(cl.Name) {
			if versions[ct.Name] != "" {
				names = append(names, ct.Name)
			}
		}
		for _, n := range cl.Nodes {
			key := cl.Name + "/" + n.Host
			live[key] = true
			if !selected || len(names) == 0 {
				continue
			}
			hk := fmt.Sprintf("%s@%s:%d", n.User, n.Host, n.Port)
			if byHost[hk] == nil {
				hosts = append(hosts, hk)
			}
			var job *pushJob
			for _, j := range byHost[hk] {
				if path.Clean(j.remoteDir) == path.Clean(cl.RemoteDir) {
					job = j
				}
			}
			if job == nil {
				job = &pushJob{node: n, remoteDir: cl.RemoteDir, clusterCerts: map[string][]string{}}
				byHost[hk] = append(byHost[hk], job)
			}
			job.clusterCerts[key] = names
			for _, name := range names {
				if !slices.Contains(job.certs, name) {
					job.certs = append(job.certs, name)
				}
			}
		}
	}

	var mu sync.Mutex
	failed := 0
	sem := make(chan struct{}, s.Cfg.SSH.Parallel)
	var wg sync.WaitGroup
	for _, hk := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, job := range byHost[hk] {
				if s.pushJob(ctx, job, versions, ps, &mu) != nil {
					mu.Lock()
					failed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	for k := range ps {
		if !live[k] {
			delete(ps, k)
		}
	}
	if err := s.Store.SavePushState(ps); err != nil {
		s.Log.Error("saving push state", "event", "push.error", "error", err)
	}
	return failed
}

func (s *Steward) pushJob(ctx context.Context, job *pushJob, versions map[string]string, ps store.PushState, mu *sync.Mutex) error {
	slices.Sort(job.certs)
	changed, err := s.Pusher.PushNode(ctx, job.node, job.remoteDir, job.certs)
	now := s.Now()
	mu.Lock()
	defer mu.Unlock()
	var keys []string
	failures := 0
	for key, names := range job.clusterCerts {
		keys = append(keys, key)
		if ps[key] == nil {
			ps[key] = map[string]*store.NodePush{}
		}
		for _, name := range names {
			np := ps[key][name]
			if np == nil {
				np = &store.NodePush{}
				ps[key][name] = np
			}
			np.LastAttempt = now
			if err != nil {
				np.Failures++
				np.LastError = err.Error()
				failures = max(failures, np.Failures)
			} else {
				np.Version, np.LastOK, np.LastError, np.Failures = versions[name], now, "", 0
			}
		}
	}
	slices.Sort(keys)
	pushed := map[string]string{}
	for _, name := range job.certs {
		pushed[name] = versions[name]
	}
	log := s.Log.With("node", job.node.Host, "clusters", keys)
	switch {
	case err != nil:
		log.Error("push failed", "event", "push.node_failed", "error", err,
			"certs", job.certs, "consecutive_failures", failures)
	case changed:
		log.Info("pushed certificates", "event", "push.node_updated", "certs", job.certs, "versions", pushed)
	default:
		log.Debug("node up to date", "event", "push.node_current", "certs", job.certs)
	}
	return err
}

// --- expiry ---

// CheckExpiry logs warnings for certificates nearing expiry, which means
// renewal has been failing.
func (s *Steward) CheckExpiry() {
	now := s.Now()
	for _, ct := range s.Cfg.Certificates {
		m, err := s.Store.Current(ct.Name)
		if err != nil || m == nil {
			if m == nil && err == nil {
				s.Log.Warn("no certificate issued yet", "event", "cert.missing", "cert", ct.Name)
			}
			continue
		}
		left := m.NotAfter.Sub(now)
		switch {
		case left <= 0:
			s.Log.Error("certificate has expired", "event", "cert.expired", "cert", ct.Name, "not_after", m.NotAfter)
		case float64(left) < float64(m.Lifetime())*s.Cfg.Renewal.WarnRemaining:
			s.Log.Warn("certificate expires soon", "event", "cert.expiry_warning", "cert", ct.Name,
				"not_after", m.NotAfter, "remaining", left.Round(time.Minute).String())
		}
	}
}

// Healthy reports whether the daemon completed a cycle recently.
func (s *Steward) Healthy() error {
	t, err := s.Store.LastHeartbeat()
	if err != nil {
		return fmt.Errorf("no heartbeat: %w", err)
	}
	limit := 2*s.Cfg.Renewal.CheckInterval.D() + 30*time.Minute
	if age := s.Now().Sub(t); age > limit {
		return fmt.Errorf("last cycle completed %s ago", age.Round(time.Second))
	}
	return nil
}
