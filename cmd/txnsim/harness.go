package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	simOrgID       = "txnsim-org"
	behaviorHeader = "X-Sim-Rubix" // tells the fake Rubix node how to answer
	cbacReason     = "policy forbids wire transfers above $10,000"
)

// ── Database safety ───────────────────────────────────────────────────────────

// resolveDBURL picks the database the run will TRUNCATE. It must never be the
// app's own database: by default it is the .env DATABASE_URL with "_txnsim"
// appended to the database name, and any explicit URL must look like a
// scratch database unless --allow-any-db is given.
func resolveDBURL(cfg Config) (string, error) {
	appURL := os.Getenv("DATABASE_URL")
	if appURL == "" {
		appURL = readDotEnv(filepath.Join(cfg.Repo, ".env"))["DATABASE_URL"]
	}
	target := cfg.DBURL
	if target == "" {
		if appURL == "" {
			return "", errors.New("no --db-url given and no DATABASE_URL in the environment or .env to derive one from")
		}
		u, err := url.Parse(appURL)
		if err != nil {
			return "", fmt.Errorf("parse DATABASE_URL: %v", err)
		}
		u.Path = "/" + strings.TrimPrefix(u.Path, "/") + "_txnsim"
		target = u.String()
	}
	tu, err := url.Parse(target)
	if err != nil || tu.Scheme == "" || strings.Trim(tu.Path, "/") == "" {
		return "", fmt.Errorf("--db-url must be a postgres:// URL with a database name, got %q", redactURL(target))
	}
	name := strings.Trim(tu.Path, "/")
	if appURL != "" && sameDatabase(target, appURL) {
		return "", fmt.Errorf("refusing to run against the app database %q: txnsim TRUNCATEs every table it touches", name)
	}
	lower := strings.ToLower(name)
	if !cfg.AllowAnyDB && !(strings.Contains(lower, "txnsim") || strings.Contains(lower, "test") || strings.Contains(lower, "sim")) {
		return "", fmt.Errorf("database %q doesn't look like a scratch database (name must contain txnsim/test/sim); pass --allow-any-db to override", name)
	}
	return target, nil
}

func sameDatabase(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	norm := func(u *url.URL) string {
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" {
			host = "localhost"
		}
		port := u.Port()
		if port == "" {
			port = "5432"
		}
		return host + ":" + port + "/" + strings.Trim(u.Path, "/")
	}
	return norm(ua) == norm(ub)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if pw, has := u.User.Password(); has && pw != "" {
		return strings.Replace(raw, ":"+pw+"@", ":***@", 1)
	}
	return raw
}

func readDotEnv(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}

// ensureDatabase creates the scratch database when it doesn't exist yet.
func ensureDatabase(ctx context.Context, dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	err = db.PingContext(ctx)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "does not exist") {
		return fmt.Errorf("connect %s: %v", redactURL(dsn), err)
	}
	u, _ := url.Parse(dsn)
	name := strings.Trim(u.Path, "/")
	u.Path = "/postgres"
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		return err
	}
	defer admin.Close()
	quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted); err != nil {
		return fmt.Errorf("database %q does not exist and creating it failed (%v) — create it yourself: CREATE DATABASE %s;", name, err, quoted)
	}
	logf("created database %s", name)
	return nil
}

// ── Fake Rubix node ───────────────────────────────────────────────────────────

// FakeRubix stands in for the Rubix node behind the middleware's /rubix proxy.
// Each request's X-Sim-Rubix header (forwarded untouched by the proxy) picks
// the answer, so a scenario can drive every success and failure mode.
type FakeRubix struct {
	srv *httptest.Server
	mu  sync.Mutex
	seq int
	log []Recorded
}

type Recorded struct {
	Method, Path, Behavior string
	Body                   []byte
}

func newFakeRubix() *FakeRubix {
	f := &FakeRubix{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *FakeRubix) nextID(prefix string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

// Received reports whether the node got a request on path with exactly body.
func (f *FakeRubix) Received(method, path string, body []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.log {
		if r.Method == method && r.Path == path && bytes.Equal(r.Body, body) {
			return true
		}
	}
	return false
}

func (f *FakeRubix) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	beh := r.Header.Get(behaviorHeader)
	f.mu.Lock()
	f.log = append(f.log, Recorded{Method: r.Method, Path: r.URL.Path, Behavior: beh, Body: body})
	f.mu.Unlock()

	switch beh {
	case "drop": // node dies mid-request: the proxy sees a broken connection
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	case "http500":
		http.Error(w, "internal node error", http.StatusInternalServerError)
		return
	case "nonjson":
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>gateway hiccup</body></html>"))
		return
	}

	switch r.URL.Path {
	case "/rubix/v1/tx":
		switch beh {
		case "fail":
			writeJSON(w, map[string]any{"status": false, "message": "insufficient balance", "result": map[string]any{"id": ""}})
		case "empty-id":
			writeJSON(w, map[string]any{"status": true, "message": "ok", "result": map[string]any{"id": ""}})
		default:
			writeJSON(w, map[string]any{"status": true, "message": "ok", "result": map[string]any{"id": f.nextID("simreq")}})
		}
	case "/rubix/v1/signature":
		child := map[string]any{"childNFTId": f.nextID("child")}
		txid := f.nextID("txid")
		switch beh {
		case "fail":
			writeJSON(w, map[string]any{"status": false, "message": "signature rejected"})
		case "no-children":
			writeJSON(w, map[string]any{"status": true, "result": map[string]any{"mintedNFTChildren": []any{}, "transactionID": txid}})
		case "empty-child":
			writeJSON(w, map[string]any{"status": true, "result": map[string]any{"mintedNFTChildren": []any{map[string]any{"childNFTId": ""}}, "transactionID": txid}})
		case "empty-txid":
			writeJSON(w, map[string]any{"status": true, "result": map[string]any{"mintedNFTChildren": []any{child}, "transactionID": ""}})
		default:
			writeJSON(w, map[string]any{"status": true, "result": map[string]any{"mintedNFTChildren": []any{child}, "transactionID": txid}})
		}
	default:
		writeJSON(w, map[string]any{"status": true, "message": "echo", "path": r.URL.Path})
	}
}

// newFakeCBAC answers GET /decisions/by-hash/{hash}; the hash prefix picks
// the outcome so scenarios can cover found / missing / malformed / failed.
func newFakeCBAC() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := strings.TrimPrefix(r.URL.Path, "/decisions/by-hash/")
		switch {
		case strings.HasPrefix(hash, "cbac-ok"):
			writeJSON(w, map[string]any{"success": true, "data": map[string]any{"reason": cbacReason}})
		case strings.HasPrefix(hash, "cbac-false"):
			writeJSON(w, map[string]any{"success": false, "message": "no decision"})
		case strings.HasPrefix(hash, "cbac-bad"):
			w.Write([]byte("{not json"))
		default:
			http.NotFound(w, r)
		}
	}))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ── Middleware process ────────────────────────────────────────────────────────

type Middleware struct {
	cmd     *exec.Cmd
	Base    string
	LogPath string
	done    chan error
}

func buildMiddleware(ctx context.Context, repo, outDir string) (string, error) {
	bin := filepath.Join(outDir, "agentdna-middleware-txnsim")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, out)
	}
	return bin, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startMiddleware runs the built binary from an empty work dir (so the repo's
// .env is never auto-loaded) with only the environment txnsim controls.
func startMiddleware(ctx context.Context, bin, outDir string, env map[string]string) (*Middleware, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	env["SERVER_PORT"] = fmt.Sprint(port)
	workDir := filepath.Join(outDir, "workdir")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, err
	}
	logPath := filepath.Join(outDir, "middleware.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(bin)
	cmd.Dir = workDir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	m := &Middleware{cmd: cmd, Base: fmt.Sprintf("http://127.0.0.1:%d", port), LogPath: logPath, done: make(chan error, 1)}
	go func() { m.done <- cmd.Wait(); logFile.Close() }()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-m.done:
			m.done <- err
			return nil, fmt.Errorf("middleware exited during startup (%v); log tail:\n%s", err, m.LogTail(30))
		case <-ctx.Done():
			m.Stop()
			return nil, ctx.Err()
		default:
		}
		if resp, err := http.Get(m.Base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return m, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	m.Stop()
	return nil, fmt.Errorf("middleware not healthy after 45s; log tail:\n%s", m.LogTail(30))
}

func (m *Middleware) Stop() {
	if m == nil || m.cmd.Process == nil {
		return
	}
	m.cmd.Process.Signal(os.Interrupt)
	select {
	case <-m.done:
	case <-time.After(3 * time.Second):
		m.cmd.Process.Kill()
		<-m.done
	}
}

func (m *Middleware) LogTail(n int) string {
	b, err := os.ReadFile(m.LogPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ── Harness ───────────────────────────────────────────────────────────────────

type SeedUser struct {
	Email, Password, Name, OldDID, DID string
}

type Harness struct {
	cfg          Config
	dbURL        string
	db           *sql.DB
	rubix        *FakeRubix
	cbac         *httptest.Server
	mw           *Middleware
	client       *http.Client
	tag          string
	user         SeedUser
	toolDID      string
	threatTitles map[int]string
}

func setup(ctx context.Context, cfg Config) (*Harness, error) {
	h := &Harness{cfg: cfg, client: &http.Client{Timeout: 60 * time.Second}}
	h.tag = fmt.Sprintf("%x", time.Now().UnixNano()&0xffffff)

	dbURL, err := resolveDBURL(cfg)
	if err != nil {
		return h, err
	}
	h.dbURL = dbURL
	logf("database   %s", redactURL(dbURL))
	if cfg.CreateDB {
		if err := ensureDatabase(ctx, dbURL); err != nil {
			return h, err
		}
	}
	if h.db, err = sql.Open("postgres", dbURL); err != nil {
		return h, err
	}
	h.db.SetMaxOpenConns(10)
	if err := h.db.PingContext(ctx); err != nil {
		return h, fmt.Errorf("connect %s: %v", redactURL(dbURL), err)
	}

	logf("building   middleware from %s", cfg.Repo)
	bin, err := buildMiddleware(ctx, cfg.Repo, cfg.OutDir)
	if err != nil {
		return h, err
	}

	h.rubix = newFakeRubix()
	h.cbac = newFakeCBAC()
	h.mw, err = startMiddleware(ctx, bin, cfg.OutDir, map[string]string{
		"DATABASE_URL":          dbURL,
		"RUBIX_NODE_URL":        h.rubix.srv.URL,
		"ORG_ID":                simOrgID,
		"CBAC_SERVICE_URL":      h.cbac.URL,
		"ADMIN_SERVICE_URL":     h.cbac.URL, // unused by txn flows; points somewhere harmless
		"CORS_ALLOWED_ORIGINS":  "http://localhost:3000",
		"SESSION_COOKIE_SECURE": "false",
	})
	if err != nil {
		return h, err
	}
	logf("middleware %s (log: %s)", h.mw.Base, h.mw.LogPath)

	if err := h.resetData(ctx); err != nil {
		return h, err
	}
	if err := h.seed(ctx); err != nil {
		return h, err
	}
	return h, nil
}

func (h *Harness) Close() {
	if h.mw != nil {
		h.mw.Stop()
	}
	if h.rubix != nil {
		h.rubix.srv.Close()
	}
	if h.cbac != nil {
		h.cbac.Close()
	}
	if h.db != nil {
		h.db.Close()
	}
}

// resetData empties every table txn ingestion writes to. Runs after the
// middleware started, so its migrations have created them all. threat_codes
// (seeded reference data) is left alone.
func (h *Harness) resetData(ctx context.Context) error {
	_, err := h.db.ExecContext(ctx, `TRUNCATE new_interactions, new_intents, threats, pending_branches,
		new_agents, new_tools, user_dids, sessions, new_org_users, new_requests, new_admins, apps
		RESTART IDENTITY CASCADE`)
	if err != nil {
		return fmt.Errorf("reset data: %v", err)
	}
	return nil
}

func (h *Harness) seed(ctx context.Context) error {
	h.user = SeedUser{
		Email:    "txnsim.user@agentdna.test",
		Password: "SimPass123!",
		Name:     "Sim User",
		OldDID:   "did:sim:" + h.tag + ":user-old",
		DID:      "did:sim:" + h.tag + ":user",
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(h.user.Password), bcrypt.MinCost)
	if err != nil {
		return err
	}
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO new_org_users (email, password, name, organization_id, api_key, did, nft_id)
		 VALUES ($1, $2, $3, $4, $5, $6, 'txnsim-user-nft')`,
		h.user.Email, string(hash), h.user.Name, simOrgID, "txnsim-key-"+h.tag, h.user.DID); err != nil {
		return fmt.Errorf("seed user: %v", err)
	}
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO user_dids (email, dids, created_at) VALUES ($3, ARRAY[$1, $2]::text[], NOW() - INTERVAL '1 day')`,
		h.user.OldDID, h.user.DID, h.user.Email); err != nil {
		return fmt.Errorf("seed user DIDs: %v", err)
	}

	h.toolDID = "did:sim:" + h.tag + ":tool-github"
	code, body, err := h.post("/core/v1/register-tool", nil, []byte(mustJSON(map[string]string{"tool_name": "GitHub (txnsim)", "tool_id": h.toolDID})))
	if err != nil || code != http.StatusOK {
		return fmt.Errorf("register tool: code=%d err=%v body=%s", code, err, body)
	}

	h.threatTitles = map[int]string{}
	rows, err := h.db.QueryContext(ctx, `SELECT code, title FROM threat_codes`)
	if err != nil {
		return fmt.Errorf("load threat codes: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c int
		var t string
		if err := rows.Scan(&c, &t); err != nil {
			return err
		}
		h.threatTitles[c] = t
	}
	return rows.Err()
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func (h *Harness) do(method, path string, headers map[string]string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.mw.Base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (h *Harness) post(path string, headers map[string]string, body []byte) (int, []byte, error) {
	return h.do(http.MethodPost, path, headers, body)
}

type TxResult struct {
	Code  int
	Body  []byte
	ReqID string
	OK    bool // tx response status:true
	Err   error
}

// SendTx submits a transaction through the middleware's /rubix proxy;
// behavior tells the fake node how to answer ("" = success).
func (h *Harness) SendTx(body []byte, behavior string) TxResult {
	code, resp, err := h.post("/rubix/v1/tx", map[string]string{behaviorHeader: behavior}, body)
	r := TxResult{Code: code, Body: resp, Err: err}
	var parsed struct {
		Status bool `json:"status"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(resp, &parsed) == nil {
		r.OK, r.ReqID = parsed.Status, parsed.Result.ID
	}
	return r
}

// SendSig confirms (or, depending on behavior, fails) a /tx request id.
func (h *Harness) SendSig(reqID, behavior string) (int, []byte, error) {
	return h.post("/rubix/v1/signature", map[string]string{behaviorHeader: behavior},
		[]byte(mustJSON(map[string]string{"id": reqID, "password": "txnsim"})))
}

// Dashboard is a logged-in browser-like client (cookie jar).
type Dashboard struct {
	h      *Harness
	client *http.Client
}

func (h *Harness) Login(email, password string) (*Dashboard, error) {
	jar, _ := cookiejar.New(nil)
	d := &Dashboard{h: h, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
	var out map[string]any
	code, err := d.call(http.MethodPost, "/dashboard/v1/login", map[string]string{"email": email, "password": password}, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("login returned %d: %v", code, out["message"])
	}
	return d, nil
}

func (d *Dashboard) call(method, path string, body any, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(mustJSON(body))
	}
	req, err := http.NewRequest(method, d.h.mw.Base+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %v (body %.200s)", path, err, b)
		}
	}
	return resp.StatusCode, nil
}

// Get fetches a dashboard endpoint and returns its "data" object.
func (d *Dashboard) Get(path string) (map[string]any, error) {
	var out struct {
		Status  bool           `json:"status"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	code, err := d.call(http.MethodGet, path, nil, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK || !out.Status {
		return nil, fmt.Errorf("GET %s: %d %s", path, code, out.Message)
	}
	return out.Data, nil
}
