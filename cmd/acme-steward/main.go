// Command acme-steward obtains TLS certificates via ACME DNS-01 (with CNAME
// delegation to a DigitalOcean zone) and pushes them to cluster nodes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/bozemanpass/acme-steward/internal/config"
	"github.com/bozemanpass/acme-steward/internal/dnscheck"
	"github.com/bozemanpass/acme-steward/internal/issuer"
	"github.com/bozemanpass/acme-steward/internal/label"
	"github.com/bozemanpass/acme-steward/internal/onboard"
	"github.com/bozemanpass/acme-steward/internal/steward"
	"github.com/bozemanpass/acme-steward/internal/store"
)

const usage = `usage: acme-steward [-config FILE] <command> [args]

Commands:
  run                      run continuously: renew when due, push to all nodes
  cycle                    run a single renew+push cycle and exit
  renew [-force] [CERT...] renew certificates that are due (or all, with -force)
  push [-cluster C]...     push current certificates to cluster nodes
  import CERT -cert F -key F [-chain F]
                           install an existing certificate as the current version
  status                   show certificate and node status
  onboard CERT|DOMAIN      print instructions for the partner, tailored to their
                           current DNS (plain text, suitable for email)
  records CERT|DOMAIN      print the required CNAME record(s) in zone-file form,
                           without any DNS lookups
  check [-wait D] [CERT|DOMAIN...]
                           verify partner DNS delegation and CAA; -wait polls
                           until ready or D elapses
  account                  register the ACME account if needed and print its URI
                           (for CAA accounturi pinning)
  validate                 validate the configuration file
  healthcheck              exit non-zero if the daemon has not completed a recent cycle

Environment:
  ACME_STEWARD_CONFIG      config file (default /etc/acme-steward/config.yaml)
  ACME_STEWARD_DATA_DIR    data directory (default /var/lib/acme-steward)
  ACME_STEWARD_LOG_LEVEL   debug|info|warn|error (default info)
  ACME_STEWARD_LOG_FORMAT  json|text (default json)
  DO_AUTH_TOKEN[_FILE]     DigitalOcean API token, or a file containing it
`

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "config file (overrides "+config.EnvConfig+")")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return 2
	}
	cmd, args := flag.Arg(0), flag.Args()[1:]

	log := newLogger()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("configuration error", "event", "config.error", "error", err)
		return 1
	}
	if cmd == "validate" {
		fmt.Printf("ok: %d certificates, %d clusters, CA %s\n", len(cfg.Certificates), len(cfg.Clusters), cfg.CADirectory)
		return 0
	}
	// Commands that only read configuration or DNS don't need the data
	// directory to be writable (or to exist).
	switch cmd {
	case "onboard":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: acme-steward onboard CERT|DOMAIN")
			return 2
		}
		return onboardCmd(cfg, &store.Store{Root: cfg.DataDir}, args[0])
	case "check":
		return check(cfg, &store.Store{Root: cfg.DataDir}, log, args)
	case "records":
		cts, err := resolveCerts(cfg, args)
		if err != nil || len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: acme-steward records CERT|DOMAIN...")
			return 2
		}
		for _, ct := range cts {
			for _, d := range baseDomains(ct) {
				fmt.Printf("%s. CNAME %s.\n", label.ChallengeName(d), label.Target(steward.DelegateLabel(ct, d), cfg.DNS.DelegateZone))
			}
		}
		return 0
	}

	st, err := store.New(cfg.DataDir)
	if err != nil {
		log.Error("opening data directory", "event", "store.error", "error", err)
		return 1
	}

	needsToken := cmd == "run" || cmd == "cycle" || cmd == "renew"
	var token string
	if needsToken {
		if token, err = config.DOToken(); err != nil {
			log.Error("configuration error", "event", "config.error", "error", err)
			return 1
		}
	}
	s := steward.New(cfg, st, log, token)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	locked := func() (func(), bool) {
		unlock, err := st.Lock()
		if err != nil {
			log.Error("cannot start", "event", "steward.locked", "error", err)
			return nil, false
		}
		return unlock, true
	}

	switch cmd {
	case "run", "cycle":
		unlock, ok := locked()
		if !ok {
			return 1
		}
		defer unlock()
		if cmd == "run" {
			_ = s.Run(ctx)
			return 0
		}
		s.Cycle(ctx)
		return 0

	case "renew":
		fs := flag.NewFlagSet("renew", flag.ExitOnError)
		force := fs.Bool("force", false, "renew even if not due, bypassing backoff and the issuance guard")
		fs.Parse(args)
		if err := checkCertNames(cfg, fs.Args()); err != nil {
			log.Error(err.Error())
			return 2
		}
		if *force && fs.NArg() == 0 {
			log.Warn("forcing renewal of every certificate", "event", "cert.force_all")
		}
		unlock, ok := locked()
		if !ok {
			return 1
		}
		defer unlock()
		if s.RenewAll(ctx, fs.Args(), *force) > 0 {
			return 1
		}
		return 0

	case "push":
		fs := flag.NewFlagSet("push", flag.ExitOnError)
		var clusters multiFlag
		fs.Var(&clusters, "cluster", "cluster to push to (repeatable; default all)")
		fs.Parse(args)
		for _, c := range clusters {
			if cfg.Cluster(c) == nil {
				log.Error("unknown cluster", "cluster", c)
				return 2
			}
		}
		unlock, ok := locked()
		if !ok {
			return 1
		}
		defer unlock()
		if s.PushAll(ctx, clusters) > 0 {
			return 1
		}
		return 0

	case "status":
		return status(cfg, st)

	case "import":
		if len(args) == 0 || cfg.Cert(args[0]) == nil {
			fmt.Fprintln(os.Stderr, "usage: acme-steward import CERT -cert FILE -key FILE [-chain FILE]")
			return 2
		}
		fs := flag.NewFlagSet("import", flag.ExitOnError)
		certFile := fs.String("cert", "", "certificate PEM (may include the chain)")
		keyFile := fs.String("key", "", "private key PEM")
		chainFile := fs.String("chain", "", "chain PEM (optional)")
		fs.Parse(args[1:])
		var files [3][]byte
		for i, f := range []string{*certFile, *keyFile, *chainFile} {
			if f == "" {
				continue
			}
			if files[i], err = os.ReadFile(f); err != nil {
				log.Error("reading import file", "error", err)
				return 1
			}
		}
		unlock, ok := locked()
		if !ok {
			return 1
		}
		defer unlock()
		if _, err := s.Import(cfg.Cert(args[0]), files[0], files[1], files[2]); err != nil {
			log.Error("import failed", "event", "cert.import_failed", "cert", args[0], "error", err)
			return 1
		}
		return 0

	case "account":
		unlock, ok := locked()
		if !ok {
			return 1
		}
		defer unlock()
		iss, err := issuer.New(cfg, st, "", log)
		if err != nil {
			log.Error("ACME account", "event", "account.error", "error", err)
			return 1
		}
		fmt.Println(iss.AccountURI())
		return 0

	case "healthcheck":
		if err := s.Healthy(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			return 1
		}
		return 0
	}
	flag.Usage()
	return 2
}

func newLogger() *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(envOr(config.EnvLogLevel, "info"))); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if envOr(config.EnvLogFormat, "json") == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	issuer.RouteLegoLogs(h)
	return slog.New(h)
}

// resolveCerts maps certificate names or domains to certificates.
func resolveCerts(cfg *config.Config, args []string) ([]*config.Certificate, error) {
	if len(args) == 0 {
		var all []*config.Certificate
		for i := range cfg.Certificates {
			all = append(all, &cfg.Certificates[i])
		}
		return all, nil
	}
	var out []*config.Certificate
	for _, a := range args {
		ct := cfg.Cert(a)
		if ct == nil {
			ct = cfg.CertForDomain(a)
		}
		if ct == nil {
			return nil, fmt.Errorf("no certificate named or containing %q in the configuration", a)
		}
		out = append(out, ct)
	}
	return out, nil
}

func checkCertNames(cfg *config.Config, names []string) error {
	for _, n := range names {
		if cfg.Cert(n) == nil {
			return fmt.Errorf("unknown certificate %q", n)
		}
	}
	return nil
}

// baseDomains returns a certificate's distinct challenge domains, keeping
// a wildcard form when present (it matters for CAA issuewild).
func baseDomains(ct *config.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range ct.Domains {
		b := label.BaseDomain(d)
		if !seen[b] {
			seen[b] = true
			out = append(out, d)
		}
	}
	return out
}

func checker(cfg *config.Config, st *store.Store) *dnscheck.Checker {
	return &dnscheck.Checker{Resolvers: cfg.DNS.Resolvers, CAAIdentifiers: cfg.DNS.CAAIdentifiers, AccountURI: accountURI(cfg, st)}
}

func onboardOptions(cfg *config.Config, st *store.Store) onboard.Options {
	return onboard.Options{
		Organization: cfg.Partner.Organization, Contact: cfg.Partner.Contact,
		CAIdentifier: cfg.DNS.CAAIdentifiers[0], CAName: cfg.Partner.CAName,
		AccountURI: accountURI(cfg, st), Pin: cfg.Partner.CAAPin,
		TTL: 3600, Now: time.Now(),
	}
}

func analyze(cfg *config.Config, st *store.Store, ct *config.Certificate) []onboard.Host {
	targets := map[string]string{}
	for _, d := range ct.Domains {
		targets[label.BaseDomain(d)] = label.Target(steward.DelegateLabel(ct, d), cfg.DNS.DelegateZone)
	}
	return onboard.Analyze(checker(cfg, st), ct.Domains, targets)
}

func onboardCmd(cfg *config.Config, st *store.Store, arg string) int {
	cts, err := resolveCerts(cfg, []string{arg})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ct := cts[0]
	o := onboardOptions(cfg, st)
	if o.AccountURI == "" && o.Pin != onboard.PinOff {
		fmt.Fprintln(os.Stderr, "note: no ACME account is registered yet, so the CAA account-pinning step is omitted; run `acme-steward account` first to include it")
	}
	hosts := analyze(cfg, st, ct)
	onboard.RenderInstructions(os.Stdout, ct.Name, hosts, onboard.Steps(hosts, o), o)
	return 0
}

func check(cfg *config.Config, st *store.Store, log *slog.Logger, args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	wait := fs.Duration("wait", 0, "keep checking until ready or this long has passed (e.g. 30m)")
	verbose := fs.Bool("v", false, "also print every individual DNS check")
	fs.Parse(args)
	cts, err := resolveCerts(cfg, fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	deadline := time.Now().Add(*wait)
	for {
		ready := true
		for _, ct := range cts {
			hosts := analyze(cfg, st, ct)
			steps := onboard.Steps(hosts, onboardOptions(cfg, st))
			if *verbose {
				printFindings(cfg, st, ct)
			}
			onboard.RenderSummary(os.Stdout, ct.Name, steps)
			result := "ready"
			if !onboard.Ready(steps) {
				result, ready = "not_ready", false
			}
			log.Info("delegation check", "event", "onboard.check", "cert", ct.Name, "result", result)
		}
		if ready {
			return 0
		}
		if time.Now().Add(time.Minute).After(deadline) {
			return 1
		}
		fmt.Println("\nchecking again in 1m...")
		time.Sleep(time.Minute)
	}
}

func printFindings(cfg *config.Config, st *store.Store, ct *config.Certificate) {
	ch := checker(cfg, st)
	var addrs []string
	for _, cn := range ct.Clusters {
		addrs = append(addrs, cfg.Cluster(cn).Addresses...)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tCHECK\tSTATUS\tDETAIL")
	for _, d := range baseDomains(ct) {
		target := label.Target(steward.DelegateLabel(ct, d), cfg.DNS.DelegateZone)
		for _, f := range ch.Check(dnscheck.Target{Domain: d, CNAME: target, Addresses: addrs}) {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Domain, f.Check, strings.ToUpper(string(f.Status)), f.Detail)
		}
	}
	tw.Flush()
	fmt.Println()
}

// accountURI is our registered account for the configured CA, or "".
func accountURI(cfg *config.Config, st *store.Store) string {
	uri, err := readAccountURI(st)
	if err != nil || uri == "" {
		return ""
	}
	host := func(u string) string {
		if p, err := url.Parse(u); err == nil {
			return p.Host
		}
		return ""
	}
	if host(uri) != host(cfg.CADirectory) {
		return ""
	}
	return uri
}

func readAccountURI(st *store.Store) (string, error) {
	b, err := os.ReadFile(st.AccountJSONPath())
	if err != nil {
		return "", err
	}
	var acct struct {
		Registration struct {
			URI string `json:"uri"`
		} `json:"registration"`
	}
	if err := json.Unmarshal(b, &acct); err != nil {
		return "", err
	}
	return acct.Registration.URI, nil
}

func status(cfg *config.Config, st *store.Store) int {
	now := time.Now()
	ps, _ := st.PushState()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CERT\tVERSION\tNOT AFTER\tRENEW AT\tFAILURES\tLAST ERROR")
	current := map[string]string{}
	for _, ct := range cfg.Certificates {
		m, _ := st.Current(ct.Name)
		cs, _ := st.CertState(ct.Name)
		ver, notAfter, renewAt := "-", "-", "-"
		if m != nil {
			ver = m.Version
			current[ct.Name] = m.Version
			notAfter = fmt.Sprintf("%s (%s)", m.NotAfter.Format(time.RFC3339), until(now, m.NotAfter))
		}
		if !cs.RenewAt.IsZero() {
			renewAt = fmt.Sprintf("%s (%s)", cs.RenewAt.Format(time.RFC3339), cs.RenewAtFrom)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", ct.Name, ver, notAfter, renewAt, cs.Failures, trunc(cs.LastError, 80))
	}
	tw.Flush()
	fmt.Println()
	fmt.Fprintln(tw, "CLUSTER\tNODE\tCERT\tSTATE\tLAST OK\tLAST ERROR")
	for _, cl := range cfg.Clusters {
		for _, n := range cl.Nodes {
			for _, ct := range cfg.CertsForCluster(cl.Name) {
				np := ps[cl.Name+"/"+n.Host][ct.Name]
				state, lastOK, lastErr := "never", "-", ""
				if np != nil {
					switch {
					case np.Version == current[ct.Name] && np.Failures == 0:
						state = "current"
					case np.Version == current[ct.Name]:
						state = "current (last push failed)"
					case np.Version == "":
						state = "never delivered"
					default:
						state = "stale"
					}
					if !np.LastOK.IsZero() {
						lastOK = np.LastOK.Format(time.RFC3339)
					}
					lastErr = trunc(np.LastError, 80)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cl.Name, n.Host, ct.Name, state, lastOK, lastErr)
			}
		}
	}
	tw.Flush()
	return 0
}

func until(now, t time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return "EXPIRED"
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
