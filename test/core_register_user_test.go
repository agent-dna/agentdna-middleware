package test

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/handler"
	"agentdna-ratelimit-auth/router"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type apiResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// fakeAdmin stands in for the admin server's POST /agent-admin/v1/users.
type fakeAdmin struct {
	mu       sync.Mutex
	calls    int
	lastBody map[string]string
	reply    func(w http.ResponseWriter)
}

func (a *fakeAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls++
	b, _ := io.ReadAll(r.Body)
	a.lastBody = nil
	json.Unmarshal(b, &a.lastBody)
	reply := a.reply
	a.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/agent-admin/v1/users" {
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		return
	}
	reply(w)
}

func (a *fakeAdmin) set(reply func(w http.ResponseWriter)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls, a.lastBody, a.reply = 0, nil, reply
}

func (a *fakeAdmin) snapshot() (int, map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls, a.lastBody
}

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./test/
// (test/run.sh starts one). Every case is documented in test/test.md.
func TestCoreRegisterUser(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	gin.SetMode(gin.TestMode)
	d := db.New(dsn)
	defer d.Close()
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	const (
		email, apiKey   = "core-register@test.local", "test-key-core-register"
		other, otherKey = "core-register-other@test.local", "test-key-core-register-other"
	)
	cleanup := func() {
		raw.Exec(`DELETE FROM user_dids WHERE email IN ($1, $2)`, email, other)
		raw.Exec(`DELETE FROM new_org_users WHERE email IN ($1, $2)`, email, other)
	}
	cleanup()
	defer cleanup()
	for _, u := range [][2]string{{email, apiKey}, {other, otherKey}} {
		if err := d.RegisterOrgUser(u[1], "test-org", "", u[0], "hash"); err != nil {
			t.Fatal(err)
		}
	}

	admin := &fakeAdmin{}
	adminSrv := httptest.NewServer(admin)
	defer adminSrv.Close()

	// newServer wires the real handler and routes against the given admin URL.
	newServer := func(adminURL string) *httptest.Server {
		backend, _ := url.Parse("http://127.0.0.1:1")
		h := handler.New(d, backend, handler.SessionConfig{}, "test-org", adminURL, "", "", "")
		r := gin.New()
		router.Register(r, h)
		return httptest.NewServer(r)
	}
	srv := newServer(adminSrv.URL)
	defer srv.Close()

	call := func(base, key, body string) (int, apiResponse) {
		req, _ := http.NewRequest(http.MethodPost, base+"/core/v1/register-user", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		var out apiResponse
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	storedDIDs := func(e string) []string {
		var s sql.NullString
		raw.QueryRow(`SELECT array_to_string(dids, ',') FROM user_dids WHERE email = $1`, e).Scan(&s)
		if s.String == "" {
			return nil
		}
		return strings.Split(s.String, ",")
	}
	primaryDID := func(e string) string {
		var did string
		raw.QueryRow(`SELECT COALESCE(did,'') FROM new_org_users WHERE email = $1`, e).Scan(&did)
		return did
	}
	expectNothingStored := func(t *testing.T) {
		t.Helper()
		if got := storedDIDs(email); len(got) != 0 {
			t.Errorf("want no stored DIDs after rollback, got %v", got)
		}
		if got := primaryDID(email); got != "none" {
			t.Errorf("want primary DID untouched (none), got %q", got)
		}
	}
	accept := func(w http.ResponseWriter) {
		w.Write([]byte(`{"status":true,"message":"user registered successfully","data":null}`))
	}

	// TC-01
	t.Run("missing API key", func(t *testing.T) {
		admin.set(accept)
		code, resp := call(srv.URL, "", `{"user_id":"did-x"}`)
		if code != http.StatusUnauthorized || resp.Status || resp.Message != "X-API-Key header is required" {
			t.Fatalf("got %d %+v", code, resp)
		}
		if calls, _ := admin.snapshot(); calls != 0 {
			t.Fatalf("admin called %d times", calls)
		}
	})

	// TC-02
	t.Run("invalid API key", func(t *testing.T) {
		admin.set(accept)
		code, resp := call(srv.URL, "no-such-key", `{"user_id":"did-x"}`)
		if code != http.StatusUnauthorized || resp.Status || resp.Message != "invalid API key" {
			t.Fatalf("got %d %+v", code, resp)
		}
		if calls, _ := admin.snapshot(); calls != 0 {
			t.Fatalf("admin called %d times", calls)
		}
	})

	// TC-03
	t.Run("missing user_id", func(t *testing.T) {
		admin.set(accept)
		code, resp := call(srv.URL, apiKey, `{}`)
		if code != http.StatusBadRequest || resp.Status || resp.Message != "user_id is required" {
			t.Fatalf("got %d %+v", code, resp)
		}
		if calls, _ := admin.snapshot(); calls != 0 {
			t.Fatalf("admin called %d times", calls)
		}
		expectNothingStored(t)
	})

	// TC-04
	t.Run("admin rejects", func(t *testing.T) {
		const msg = "failed to register user (id: did-rejected): The email or user ID is already registered"
		admin.set(func(w http.ResponseWriter) {
			w.Write([]byte(`{"status":false,"message":"` + msg + `","data":null}`))
		})
		code, resp := call(srv.URL, apiKey, `{"user_id":"did-rejected"}`)
		if code != http.StatusConflict || resp.Status || resp.Message != msg {
			t.Fatalf("got %d %+v", code, resp)
		}
		if calls, _ := admin.snapshot(); calls != 1 {
			t.Fatalf("want 1 admin call, got %d", calls)
		}
		expectNothingStored(t)
	})

	// TC-05
	t.Run("admin returns non-JSON body", func(t *testing.T) {
		admin.set(func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`<html>502 Bad Gateway</html>`))
		})
		code, resp := call(srv.URL, apiKey, `{"user_id":"did-bad-body"}`)
		if code != http.StatusInternalServerError || resp.Status || !strings.Contains(resp.Message, "invalid response from admin server") {
			t.Fatalf("got %d %+v", code, resp)
		}
		expectNothingStored(t)
	})

	// TC-06
	t.Run("admin unreachable", func(t *testing.T) {
		down := httptest.NewServer(http.NotFoundHandler())
		down.Close()
		s := newServer(down.URL)
		defer s.Close()
		code, resp := call(s.URL, apiKey, `{"user_id":"did-unreachable"}`)
		if code != http.StatusInternalServerError || resp.Status || !strings.Contains(resp.Message, "failed to reach admin server") {
			t.Fatalf("got %d %+v", code, resp)
		}
		expectNothingStored(t)
	})

	// TC-07: waits out the real 10s admin client timeout.
	t.Run("admin times out after 10s", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waits 10s; skipped with -short")
		}
		admin.set(func(w http.ResponseWriter) {
			time.Sleep(12 * time.Second)
			accept(w)
		})
		start := time.Now()
		code, resp := call(srv.URL, apiKey, `{"user_id":"did-timeout"}`)
		elapsed := time.Since(start)
		if code != http.StatusInternalServerError || resp.Status || !strings.Contains(resp.Message, "Timeout") {
			t.Fatalf("got %d %+v", code, resp)
		}
		if elapsed < 9*time.Second || elapsed > 11*time.Second {
			t.Fatalf("want ~10s timeout, took %v", elapsed)
		}
		expectNothingStored(t)
	})

	// TC-08
	t.Run("admin accepts", func(t *testing.T) {
		admin.set(accept)
		code, resp := call(srv.URL, apiKey, `{"user_id":"did-ok"}`)
		if code != http.StatusOK || !resp.Status {
			t.Fatalf("got %d %+v", code, resp)
		}
		calls, body := admin.snapshot()
		if calls != 1 {
			t.Fatalf("want 1 admin call, got %d", calls)
		}
		for k, v := range map[string]string{"user_id": "did-ok", "email": email, "api_key": apiKey} {
			if body[k] != v {
				t.Errorf("admin body %s: want %q, got %q", k, v, body[k])
			}
		}
		if got := storedDIDs(email); len(got) != 1 || got[0] != "did-ok" {
			t.Fatalf("want stored [did-ok], got %v", got)
		}
		if got := primaryDID(email); got != "did-ok" {
			t.Fatalf("want primary did-ok, got %q", got)
		}
	})

	// TC-09
	t.Run("DID held by another user", func(t *testing.T) {
		admin.set(accept)
		code, resp := call(srv.URL, otherKey, `{"user_id":"did-ok"}`)
		if code != http.StatusConflict || resp.Status || resp.Message != "this DID is already registered to another user" {
			t.Fatalf("got %d %+v", code, resp)
		}
		if calls, _ := admin.snapshot(); calls != 0 {
			t.Fatalf("admin should not be called, got %d calls", calls)
		}
		if got := storedDIDs(other); len(got) != 0 {
			t.Fatalf("want no DIDs for other user, got %v", got)
		}
	})

	// TC-10: documents current behaviour — the admin server rejects a second
	// registration for the same email, so an existing user can't add a DID.
	t.Run("second DID for registered user is rejected by admin", func(t *testing.T) {
		const msg = "failed to register user (id: did-second): The email or user ID is already registered"
		admin.set(func(w http.ResponseWriter) {
			w.Write([]byte(`{"status":false,"message":"` + msg + `","data":null}`))
		})
		code, resp := call(srv.URL, apiKey, `{"user_id":"did-second"}`)
		if code != http.StatusConflict || resp.Message != msg {
			t.Fatalf("got %d %+v", code, resp)
		}
		if got := storedDIDs(email); len(got) != 1 || got[0] != "did-ok" {
			t.Fatalf("want stored DIDs unchanged [did-ok], got %v", got)
		}
		if got := primaryDID(email); got != "did-ok" {
			t.Fatalf("want primary unchanged did-ok, got %q", got)
		}
	})
}
