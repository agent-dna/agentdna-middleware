// Command txnsim drives the AgentDNA middleware end to end the way agent
// runtimes do: it submits transactions through the /rubix proxy, plays the
// Rubix node (and the CBAC decision service) to answer them with every
// success and failure mode, then checks what landed in the database and what
// the dashboard API shows. See cmd/txnsim/README.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	DBURL      string
	Repo       string
	OutDir     string
	Run        string
	List       bool
	Strict     bool
	CreateDB   bool
	AllowAnyDB bool
	Verbose    bool
	Timeout    time.Duration
}

func main() { os.Exit(run()) }

func run() int {
	var cfg Config
	flag.StringVar(&cfg.DBURL, "db-url", "", "scratch Postgres URL (default: .env DATABASE_URL with _txnsim appended to the db name). ALL ITS DATA IS TRUNCATED.")
	flag.StringVar(&cfg.Repo, "repo", ".", "middleware repository root to build")
	flag.StringVar(&cfg.OutDir, "out", "txnsim-out", "directory for the built binary, middleware.log and report.json")
	flag.StringVar(&cfg.Run, "run", "", "only run scenarios whose ID or name matches this regexp")
	flag.BoolVar(&cfg.List, "list", false, "list scenarios and exit")
	flag.BoolVar(&cfg.Strict, "strict", false, "exit non-zero on warnings too")
	flag.BoolVar(&cfg.CreateDB, "create-db", true, "create the scratch database if it doesn't exist")
	flag.BoolVar(&cfg.AllowAnyDB, "allow-any-db", false, "allow a database whose name doesn't contain txnsim/test/sim")
	flag.BoolVar(&cfg.Verbose, "v", false, "print notes for passing scenarios and middleware log tails for failing ones")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Minute, "overall time limit")
	flag.Parse()

	scenarios := allScenarios()
	if cfg.Run != "" {
		re, err := regexp.Compile("(?i)" + cfg.Run)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad --run: %v\n", err)
			return 2
		}
		var keep []Scenario
		for _, s := range scenarios {
			if re.MatchString(s.ID) || re.MatchString(s.Name) {
				keep = append(keep, s)
			}
		}
		scenarios = keep
	}
	if cfg.List {
		for _, s := range scenarios {
			fmt.Printf("%-4s %-11s %s\n", s.ID, s.Kind, s.Name)
		}
		return 0
	}
	if len(scenarios) == 0 {
		fmt.Fprintln(os.Stderr, "no scenarios match --run")
		return 2
	}

	var err error
	if cfg.Repo, err = filepath.Abs(cfg.Repo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cfg.OutDir, err = filepath.Abs(cfg.OutDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	started := time.Now()
	h, err := setup(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nsetup failed: %v\n", err)
		if h != nil {
			h.Close()
		}
		return 2
	}
	defer h.Close()

	fmt.Printf("\nrunning %d scenario(s)\n\n", len(scenarios))
	var results []*Result
	for _, s := range scenarios {
		if ctx.Err() != nil {
			fmt.Println("\naborted:", ctx.Err())
			break
		}
		r := runScenario(h, s)
		results = append(results, r)
		printResult(r, cfg.Verbose, h)
	}
	return summarize(cfg, h, results, time.Since(started))
}

// ── Scenario framework ────────────────────────────────────────────────────────

type Scenario struct {
	ID, Kind, Name string
	Run            func(t *T)
}

type Status string

const (
	Pass Status = "PASS"
	Warn Status = "WARN"
	Fail Status = "FAIL"
)

type Result struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Status     Status   `json:"status"`
	DurationMs int64    `json:"durationMs"`
	Fails      []string `json:"fails,omitempty"`
	Warns      []string `json:"warns,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// T is a scenario's context: assertion recording plus helpers that keep its
// ids (NFTs, DIDs, envelope hashes) unique to this run and scenario.
type T struct {
	h       *Harness
	s       Scenario
	fails   []string
	warns   []string
	notes   []string
	tracked []string
}

type fatalSignal struct{}

func (t *T) Failf(f string, a ...any) { t.fails = append(t.fails, fmt.Sprintf(f, a...)) }
func (t *T) Warnf(f string, a ...any) { t.warns = append(t.warns, fmt.Sprintf(f, a...)) }
func (t *T) Notef(f string, a ...any) { t.notes = append(t.notes, fmt.Sprintf(f, a...)) }

// Fatalf records a failure and stops the scenario.
func (t *T) Fatalf(f string, a ...any) {
	t.Failf(f, a...)
	panic(fatalSignal{})
}

func (t *T) Check(ok bool, f string, a ...any) bool {
	if !ok {
		t.Failf(f, a...)
	}
	return ok
}

func (t *T) Equal(label string, got, want any) bool {
	if reflect.DeepEqual(got, want) {
		return true
	}
	t.Failf("%s: got %v, want %v", label, got, want)
	return false
}

// Must stops the scenario on an infrastructure error (DB/HTTP failure).
func (t *T) Must(err error, what string) {
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// Track registers an intent for the post-scenario invariant check.
func (t *T) Track(intentIDs ...string) { t.tracked = append(t.tracked, intentIDs...) }

func (t *T) key() string            { return strings.ToLower(t.s.ID) }
func (t *T) NFT(name string) string { return fmt.Sprintf("txnsim-%s-%s-%s", t.h.tag, t.key(), name) }
func (t *T) DID(name string) string { return fmt.Sprintf("did:sim:%s:%s:%s", t.h.tag, t.key(), name) }

// Actor returns a DID registered as an agent of the seeded user, the state an
// SDK actor is in once registered: the middleware rejects any txn naming an
// unregistered DID. Use DID for one that must stay unregistered.
func (t *T) Actor(name string) string {
	did := t.DID(name)
	if _, err := t.h.db.Exec(
		`INSERT INTO new_agents (did, name, deployer_did, organization_id) VALUES ($1, $2, $3, $4) ON CONFLICT (did) DO NOTHING`,
		did, "Sim "+name, t.h.user.DID, simOrgID); err != nil {
		t.Fatalf("register actor %s: %v", name, err)
	}
	return did
}
func (t *T) Builder(name string) *Builder {
	return NewBuilder(fmt.Sprintf("%s-%s-%s", t.h.tag, t.key(), name))
}

func runScenario(h *Harness, s Scenario) *Result {
	t := &T{h: h, s: s}
	start := time.Now()
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(fatalSignal); !ok {
					t.Failf("panic: %v\n%s", r, debug.Stack())
				}
			}
		}()
		s.Run(t)
	}()
	seen := map[string]bool{}
	for _, id := range t.tracked {
		if seen[id] {
			continue
		}
		seen[id] = true
		fails, warns := h.CheckInvariants(id)
		for _, f := range fails {
			t.Failf("invariant [%s]: %s", id, f)
		}
		for _, w := range warns {
			t.Warnf("invariant [%s]: %s", id, w)
		}
	}
	r := &Result{ID: s.ID, Kind: s.Kind, Name: s.Name, DurationMs: time.Since(start).Milliseconds(),
		Fails: t.fails, Warns: t.warns, Notes: t.notes, Status: Pass}
	switch {
	case len(t.fails) > 0:
		r.Status = Fail
	case len(t.warns) > 0:
		r.Status = Warn
	}
	return r
}

// ── Output ────────────────────────────────────────────────────────────────────

var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func statusLabel(s Status) string {
	switch s {
	case Pass:
		return paint("32", "PASS")
	case Warn:
		return paint("33", "WARN")
	default:
		return paint("31;1", "FAIL")
	}
}

func logf(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }

func printResult(r *Result, verbose bool, h *Harness) {
	fmt.Printf("[%s] %-4s %-11s %s %s\n", statusLabel(r.Status), r.ID, r.Kind, r.Name, paint("90", fmt.Sprintf("(%dms)", r.DurationMs)))
	for _, f := range r.Fails {
		fmt.Printf("       %s %s\n", paint("31", "✗"), indent(f))
	}
	for _, w := range r.Warns {
		fmt.Printf("       %s %s\n", paint("33", "!"), indent(w))
	}
	if verbose || r.Status != Pass {
		for _, n := range r.Notes {
			fmt.Printf("       %s %s\n", paint("90", "·"), indent(n))
		}
	}
	if verbose && r.Status == Fail && h.mw != nil {
		fmt.Println(paint("90", "       middleware log tail:\n"+indentAll(h.mw.LogTail(15), "         ")))
	}
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n         ") }

func indentAll(s, pad string) string { return pad + strings.ReplaceAll(s, "\n", "\n"+pad) }

func summarize(cfg Config, h *Harness, results []*Result, elapsed time.Duration) int {
	counts := map[Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	fmt.Printf("\n%s  %d passed, %d warned, %d failed  in %s\n",
		paint("1", "summary"), counts[Pass], counts[Warn], counts[Fail], elapsed.Round(time.Millisecond))

	if counts[Fail] > 0 {
		var ids []string
		for _, r := range results {
			if r.Status == Fail {
				ids = append(ids, r.ID)
			}
		}
		sort.Strings(ids)
		fmt.Printf("failed: %s\n", strings.Join(ids, ", "))
	}

	reportPath := filepath.Join(cfg.OutDir, "report.json")
	report := map[string]any{
		"startedAt":     time.Now().Add(-elapsed).UTC().Format(time.RFC3339),
		"durationMs":    elapsed.Milliseconds(),
		"database":      redactURL(h.dbURL),
		"middlewareLog": h.mw.LogPath,
		"runTag":        h.tag,
		"summary":       map[string]int{"pass": counts[Pass], "warn": counts[Warn], "fail": counts[Fail]},
		"scenarios":     results,
	}
	if b, err := json.MarshalIndent(report, "", "  "); err == nil {
		if err := os.WriteFile(reportPath, b, 0o644); err == nil {
			fmt.Printf("report:  %s\nlog:     %s\n", reportPath, h.mw.LogPath)
		}
	}
	fmt.Printf("data left in %s for inspection (run tag %s)\n", redactURL(h.dbURL), h.tag)

	if counts[Fail] > 0 || (cfg.Strict && counts[Warn] > 0) {
		return 1
	}
	return 0
}
