package main

// Warning (51xx) scenarios. Everything goes through the real paths: intents
// through the /rubix proxy, auth evidence through POST /core/v1/auth-evidence,
// trust and credential changes through the admin dashboard endpoints, and
// results are read back from the database and the dashboard API.
//
// auth_evidence, resource_bases and credentials are not truncated between
// runs, so every host and credential name carries the run tag and scenario.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func warningScenarios() []Scenario {
	return []Scenario{
		{"W01", "warnings", "evidence before the intent: untrusted destination gives 5101 on the calling hop", scWarnEvidenceFirst},
		{"W02", "warnings", "intent before the evidence: late evidence still sets 5101", scWarnIntentFirst},
		{"W03", "warnings", "admin trust changes add and clear 5101, and only for that resource", scWarnTrustChanges},
		{"W04", "warnings", "path-prefix trust: only paths under a Flagged prefix warn", scWarnPathPrefix},
		{"W05", "warnings", "a key reaching a second resource marks its earlier intent too (5105)", scWarnSharedKey},
		{"W06", "warnings", "credential status changes add and clear 5107, and only for that key", scWarnCredentialStatus},
		{"W07", "warnings", "a key first seen longer ago than DURATION_CREDENTIAL gives 5108", scWarnOldKey},
		{"W08", "warnings", "messy evidence: odd spellings, NULLs, empty, invalid and repeated records", scWarnMessyEvidence},
		{"W09", "warnings", "51xx codes in envelopes are ignored; a real threat sits beside a warning", scWarnEnvelopeCodes},
		{"W10", "warnings", "dashboard API shows warnings on hops, intents, agents and credentials", scWarnDashboard},
		{"W11", "warnings", "a later txn on the same intent: new hops get warnings, old hops keep theirs", scWarnGrowingIntent},
		{"W12", "warnings", "evidence and intents racing in parallel all end with their warnings", scWarnRace},
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// wEv is one auth evidence record as an observation point sends it.
type wEv map[string]any

func (t *T) wHost(name string) string {
	return fmt.Sprintf("%s-%s-%s.wsim.test", name, t.h.tag, t.key())
}

func (t *T) wCred(name string) string {
	return fmt.Sprintf("wcred-%s-%s-%s", t.h.tag, t.key(), name)
}

// wOut is a server_out record: the tool called dest with cred. The request
// id is filled in by whoever posts it.
func wOut(dest, cred string) wEv {
	return wEv{"source": "server_out", "destination": dest, "credential_id": cred, "auth_method": "api_key", "auth_status": "accepted", "key_version": "kv1"}
}

// wPlumbing is what the agent's client and the tool's server record for every
// request: the local hop and the tool's own DID. Neither is a called service.
func wPlumbing(req, toolDID, cred string) []wEv {
	return []wEv{
		{"request_id": req, "source": "client_out", "destination": "127.0.0.1", "credential_id": cred, "auth_method": "bearer_opaque", "auth_status": "accepted"},
		{"request_id": req, "source": "server_in", "destination": toolDID, "credential_id": cred, "auth_method": "bearer_opaque", "auth_status": "unknown"},
	}
}

// wEvidence posts records with the sim user's API key and returns how many
// the middleware stored.
func (t *T) wEvidence(recs ...wEv) int {
	if recs == nil {
		recs = []wEv{}
	}
	code, body, err := t.h.post("/core/v1/auth-evidence", map[string]string{"X-API-Key": "txnsim-key-" + t.h.tag},
		[]byte(mustJSON(map[string]any{"records": recs})))
	t.Must(err, "POST /core/v1/auth-evidence")
	if code != http.StatusOK {
		t.Fatalf("POST /core/v1/auth-evidence: HTTP %d %.300s", code, body)
	}
	var out struct {
		Data struct {
			Stored int `json:"stored"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("auth-evidence response: %v", err)
	}
	return out.Data.Stored
}

// wCalls sets the request id on each call record and appends the plumbing.
func wCalls(req, toolDID, plumbingCred string, calls ...wEv) []wEv {
	recs := wPlumbing(req, toolDID, plumbingCred)
	for _, c := range calls {
		r := wEv{"request_id": req}
		for k, v := range c {
			r[k] = v
		}
		recs = append(recs, r)
	}
	return recs
}

// wRun runs U → agent → tool, with the tool making calls while serving the
// agent's request. evidenceFirst posts the evidence before the intent (the
// usual order), otherwise after. Returns the intent id and the request
// (agent's envelope) signature.
func (t *T) wRun(name, agent string, evidenceFirst bool, calls ...wEv) (string, string) {
	U, tool := t.h.user.DID, t.h.toolDID
	b := t.Builder(name)
	u := b.Root(U, Payload("please run "+name))
	a := b.Next(u, agent, Payload("calling the tool for "+name))
	x := b.Next(a, tool, Payload("done: "+name))
	nft := t.NFT(name)
	recs := wCalls(a.Sig, tool, t.wCred("session"), calls...)
	if evidenceFirst {
		t.wEvidence(recs...)
	}
	res := t.intent(nft, U, x, "", "ok")
	t.Check(res.Code == http.StatusOK && res.OK, "%s: tx passthrough HTTP %d status=%v", name, res.Code, res.OK)
	if !evidenceFirst {
		t.wEvidence(recs...)
	}
	return nft, a.Sig
}

// wCodes returns each hop's warning_codes, keyed by interaction id.
func (t *T) wCodes(intentID string) map[string][]int64 {
	rows, err := t.h.db.Query(`SELECT interaction_id, warning_codes FROM new_interactions WHERE intent_id = $1`, intentID)
	t.Must(err, "read warning_codes")
	defer rows.Close()
	out := map[string][]int64{}
	for rows.Next() {
		var id string
		var codes []int64
		t.Must(rows.Scan(&id, pq.Array(&codes)), "scan warning_codes")
		if codes == nil {
			codes = []int64{}
		}
		out[id] = codes
	}
	return out
}

// wExpect checks the warnings on every hop of intentID: hops from→to in want
// carry exactly those codes, every other hop carries none.
func (t *T) wExpect(label, intentID string, want map[pair][]int64) {
	rows := t.rows(intentID)
	if len(rows) == 0 {
		t.Failf("%s: intent %s has no hops", label, intentID)
		return
	}
	codes := t.wCodes(intentID)
	found := map[pair]bool{}
	for _, r := range rows {
		p := pair{r.From, r.To}
		w, listed := want[p]
		if w == nil {
			w = []int64{}
		}
		if listed {
			found[p] = true
		}
		if got := codes[r.ID]; !reflect.DeepEqual(got, w) {
			t.Failf("%s: hop %s (%s) warning_codes = %v, want %v", label, r.ID, p, got, w)
		}
	}
	for p := range want {
		if !found[p] {
			t.Failf("%s: no hop %s in intent %s", label, p, intentID)
		}
	}
}

// wBase gives host (or host/path) a trust status directly, before any
// traffic, as the ops script loading known services does.
func (t *T) wBase(baseURL, status string) {
	if _, err := t.h.db.Exec(`INSERT INTO resource_bases (base_url, name, trust_status) VALUES ($1, $1, $2)
		ON CONFLICT (host, path_prefix) DO UPDATE SET trust_status = EXCLUDED.trust_status`, baseURL, status); err != nil {
		t.Fatalf("resource base %s: %v", baseURL, err)
	}
}

// wAdmin returns a dashboard session with admin rights: an org user whose
// email is also registered as an admin. Created once per run.
func (t *T) wAdmin() *Dashboard {
	h := t.h
	h.adminOnce.Do(func() {
		email, pw := "txnsim.admin+"+h.tag+"@agentdna.test", "SimAdmin123!"
		did := "did:sim:" + h.tag + ":admin"
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		if err != nil {
			h.adminErr = err
			return
		}
		if _, err := h.db.Exec(`INSERT INTO new_org_users (email, password, name, organization_id, api_key, did, nft_id)
			VALUES ($1, $2, 'Sim Admin', $3, $4, $5, 'txnsim-admin-nft')`, email, string(hash), simOrgID, "txnsim-admin-key-"+h.tag, did); err != nil {
			h.adminErr = fmt.Errorf("seed admin user: %v", err)
			return
		}
		if _, err := h.db.Exec(`INSERT INTO new_admins (did, organization_id, api_key, email) VALUES ($1, $2, $3, $4)`,
			did, simOrgID, "txnsim-admin-key-"+h.tag, email); err != nil {
			h.adminErr = fmt.Errorf("seed admin: %v", err)
			return
		}
		h.admin, h.adminErr = h.Login(email, pw)
	})
	if h.adminErr != nil {
		t.Fatalf("admin session: %v", h.adminErr)
	}
	return h.admin
}

func (t *T) wAdminPost(path string, body map[string]string) {
	var out struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	code, err := t.wAdmin().call(http.MethodPost, path, body, &out)
	t.Must(err, "POST "+path)
	if code != http.StatusOK || !out.Status {
		t.Fatalf("POST %s %v: HTTP %d %s", path, body, code, out.Message)
	}
}

func (t *T) wSetTrust(resourceID, status string) {
	t.wAdminPost("/dashboard/v1/update-resource-trust-status", map[string]string{"resourceID": resourceID, "trustStatus": status})
}

func (t *T) wSetCredential(cred, status string) {
	t.wAdminPost("/dashboard/v1/update-credential-status", map[string]string{"credentialID": cred, "status": status, "reason": "txnsim"})
}

// wJSONCodes reads the "code" of each item of a warnings array from a
// decoded JSON response, failing if it is missing or not an array.
func (t *T) wJSONCodes(label string, v any) []int64 {
	list, ok := v.([]any)
	if !ok {
		t.Failf("%s: warnings is %T (%v), want an array", label, v, v)
		return nil
	}
	codes := []int64{}
	for _, it := range list {
		m, _ := it.(map[string]any)
		c, _ := m["code"].(float64)
		if title, _ := m["title"].(string); title == "" {
			t.Failf("%s: warning %v has no title", label, m)
		}
		codes = append(codes, int64(c))
	}
	return codes
}

// wJSONCounts is wJSONCodes for counted warnings: code → count.
func (t *T) wJSONCounts(label string, v any) map[int64]int {
	list, ok := v.([]any)
	if !ok {
		t.Failf("%s: warnings is %T (%v), want an array", label, v, v)
		return nil
	}
	out := map[int64]int{}
	for _, it := range list {
		m, _ := it.(map[string]any)
		c, _ := m["code"].(float64)
		n, _ := m["count"].(float64)
		out[int64(c)] = int(n)
	}
	return out
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

func scWarnEvidenceFirst(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent"), t.h.toolDID
	nft, reqSig := t.wRun("intent", A, true, wOut("POST https://"+t.wHost("unknown")+"/v1/charge", ""))

	for _, r := range t.rows(nft) {
		if r.From == A && r.To == tool {
			t.Equal("the A→tool hop's signature is the request id the evidence names", r.Sig, reqSig)
		}
	}
	// Only the hop the tool served carries the warning; the client_out
	// (127.0.0.1) and server_in (tool DID) rows on it must not count.
	t.wExpect("evidence first", nft, map[pair][]int64{{A, tool}: {5101}, {U, A}: nil, {tool, U}: nil})
}

func scWarnIntentFirst(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent"), t.h.toolDID
	b := t.Builder("intent")
	a := b.Next(b.Root(U), A)
	x := b.Next(a, tool)
	nft := t.NFT("intent")
	t.intent(nft, U, x, "", "ok")
	t.wExpect("before any evidence", nft, map[pair][]int64{{A, tool}: nil})

	stored := t.wEvidence(wCalls(a.Sig, tool, t.wCred("session"), wOut("https://"+t.wHost("late")+"/x", ""))...)
	t.Equal("records stored", stored, 3)
	t.wExpect("after late evidence", nft, map[pair][]int64{{A, tool}: {5101}})
}

func scWarnTrustChanges(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	host, other := t.wHost("svc"), t.wHost("other")
	nft, _ := t.wRun("intent", A, true, wOut("GET https://"+host+"/v1/items", ""))
	nft2, _ := t.wRun("bystander", A, true, wOut("GET https://"+other+"/v1/items", ""))
	t.wExpect("new host", nft, map[pair][]int64{{A, tool}: {5101}})

	steps := []struct {
		status string
		want   []int64
	}{
		{"Trusted", nil},
		{"Flagged", []int64{5101}},
		{"Unreviewed", []int64{5101}},
		{"Trusted", nil},
	}
	for _, s := range steps {
		t.wSetTrust(host, s.status)
		t.wExpect("after "+s.status, nft, map[pair][]int64{{A, tool}: s.want})
	}
	// A different resource is untouched by all of that.
	t.wExpect("other resource", nft2, map[pair][]int64{{A, tool}: {5101}})
}

func scWarnPathPrefix(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	host := t.wHost("docs")
	t.wBase(host, "Trusted")
	t.wBase(host+"/private", "Flagged")

	cases := []struct {
		name, path string
		want       []int64
	}{
		{"public", "/public/handbook", nil},
		{"private-file", "/private/payroll.pdf", []int64{5101}},
		{"private-exact", "/private", []int64{5101}},
		{"privateer", "/privateer/notes", nil}, // shares the letters, not the path
		{"root", "", nil},
	}
	for _, c := range cases {
		nft, _ := t.wRun(c.name, A, true, wOut("GET https://"+host+c.path, ""))
		t.wExpect(c.name, nft, map[pair][]int64{{A, tool}: c.want})
	}
}

func scWarnSharedKey(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	h1, h2 := t.wHost("crm"), t.wHost("mail")
	t.wBase(h1, "Trusted")
	t.wBase(h2, "Trusted")
	key, key2 := t.wCred("shared"), t.wCred("one-service")

	first, _ := t.wRun("first", A, true, wOut("GET https://"+h1+"/contacts", key))
	t.wExpect("key on one resource", first, map[pair][]int64{{A, tool}: nil})

	second, _ := t.wRun("second", A, true, wOut("POST https://"+h2+"/send", key))
	t.wExpect("key's second resource", second, map[pair][]int64{{A, tool}: {5105}})
	t.wExpect("earlier intent with the same key", first, map[pair][]int64{{A, tool}: {5105}})

	// Different spellings of one service are one resource, not two.
	third, _ := t.wRun("spellings", A, true,
		wOut("GET https://"+h1+"/a", key2),
		wOut("POST https://WWW."+strings.ToUpper(h1)+":443/b/?q=1", key2),
		wOut(h1, key2))
	t.wExpect("one resource, many spellings", third, map[pair][]int64{{A, tool}: nil})
}

func scWarnCredentialStatus(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	host := t.wHost("api")
	t.wBase(host, "Trusted")
	key, other := t.wCred("key"), t.wCred("other")
	nft, _ := t.wRun("intent", A, true, wOut("GET https://"+host+"/v1", key))
	nft2, _ := t.wRun("bystander", A, true, wOut("GET https://"+host+"/v1", other))
	t.wExpect("healthy key", nft, map[pair][]int64{{A, tool}: nil})

	for _, s := range []struct {
		status string
		want   []int64
	}{
		{"flagged", []int64{5107}},
		{"compromised", []int64{5107}},
		{"active", nil},
	} {
		t.wSetCredential(key, s.status)
		t.wExpect("key "+s.status, nft, map[pair][]int64{{A, tool}: s.want})
		t.wExpect("other key while this one is "+s.status, nft2, map[pair][]int64{{A, tool}: nil})
	}
}

func scWarnOldKey(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	host := t.wHost("api")
	t.wBase(host, "Trusted")
	old, fresh, untimed := t.wCred("old"), t.wCred("fresh"), t.wCred("untimed")

	// The old key's first use: 200 days ago, on a request that never became
	// an interaction (evidence only). Same resource, so no 5105.
	longAgo := float64(time.Now().AddDate(0, 0, -200).Unix())
	stored := t.wEvidence(wEv{"request_id": t.NFT("orphan-old"), "source": "server_out", "destination": "GET https://" + host + "/legacy",
		"credential_id": old, "auth_method": "api_key", "auth_status": "accepted", "observed_at": longAgo})
	t.Equal("orphan record stored", stored, 1)

	nft, _ := t.wRun("old", A, true, wOut("GET https://"+host+"/v1", old))
	t.wExpect("key first used 200 days ago", nft, map[pair][]int64{{A, tool}: {5108}})

	yesterday := float64(time.Now().AddDate(0, 0, -1).Unix())
	call := wOut("GET https://"+host+"/v1", fresh)
	call["observed_at"] = yesterday
	nft2, _ := t.wRun("fresh", A, true, call)
	t.wExpect("key first used yesterday", nft2, map[pair][]int64{{A, tool}: nil})

	// No observed_at: the database stamps it now, so it's a new key.
	nft3, _ := t.wRun("untimed", A, true, wOut("GET https://"+host+"/v1", untimed))
	t.wExpect("key with no observed time", nft3, map[pair][]int64{{A, tool}: nil})
}

func scWarnMessyEvidence(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent"), t.h.toolDID
	host := t.wHost("api")
	t.wBase(host, "Trusted")
	b := t.Builder("intent")
	a := b.Next(b.Root(U), A)
	x := b.Next(a, tool)
	nft := t.NFT("intent")

	recs := []wEv{
		// Not stored: request_id and source are required.
		{"source": "server_out", "destination": "https://" + host},
		{"request_id": a.Sig, "destination": "https://" + host},
		// Spellings of the Trusted host: case, www., default port, query,
		// fragment, trailing slash, userinfo, bare host. None may warn.
		{"request_id": a.Sig, "source": "server_out", "destination": "POST https://WWW." + strings.ToUpper(host) + ":443/v1/x/?q=1#frag", "identity_id": nil, "identity_name": nil},
		{"request_id": a.Sig, "source": "server_out", "destination": "https://svc:hunter2@" + strings.ToUpper(host) + "/a", "auth_method": "basic"},
		{"request_id": a.Sig, "source": "server_out", "destination": host},
		// Empty destination and no credential fields at all.
		{"request_id": a.Sig, "source": "server_out", "destination": ""},
		// Explicit JSON nulls everywhere optional.
		{"request_id": a.Sig, "source": "server_in", "destination": tool, "credential_id": nil, "auth_method": nil, "identity_id": nil, "observed_at": nil},
		// A request that never becomes an interaction.
		{"request_id": t.NFT("never-landed"), "source": "server_out", "destination": "https://" + t.wHost("ghost")},
		// The tool's answer hop: a non-URL and a long unicode URL. Both are
		// unknown hosts, so this hop warns.
		{"request_id": x.Sig, "source": "server_out", "destination": "not a url at all"},
		{"request_id": x.Sig, "source": "server_out", "destination": "GET https://bücher-" + t.h.tag + ".wsim.test/" + strings.Repeat("katalog/", 300)},
	}
	stored := t.wEvidence(recs...)
	t.Equal("records stored (2 invalid skipped)", stored, len(recs)-2)
	t.Equal("same batch again stores nothing", t.wEvidence(recs...), 0)
	t.Equal("empty batch", t.wEvidence(), 0)

	t.intent(nft, U, x, "", "ok")
	t.wExpect("messy evidence", nft, map[pair][]int64{{U, A}: nil, {A, tool}: nil, {tool, U}: {5101}})
}

func scWarnEnvelopeCodes(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent"), t.h.toolDID

	// An agent stamping a warning code on its own envelope changes nothing:
	// warnings come only from the middleware's own checks.
	b := t.Builder("stamped")
	a := b.Next(b.Root(U), A, Code(5101))
	x := b.Next(a, tool, Code(5107))
	nft := t.NFT("stamped")
	t.intent(nft, U, x, "", "ok")
	for _, r := range t.rows(nft) {
		t.Check(!r.Threat, "hop %s: an envelope's 51xx code made it a threat", r.ID)
	}
	t.Equal("threat rows for 51xx envelope codes", len(t.threats(nft)), 0)
	t.Equal("intent threat flag", t.intentRow(nft).Threat, false)
	t.wExpect("51xx in envelopes", nft, map[pair][]int64{{U, A}: nil, {A, tool}: nil, {tool, U}: nil})

	// A real threat (1001 whitelist) and a warning on the same hop.
	b2 := t.Builder("both")
	a2 := b2.Next(b2.Root(U), A, Code(1001), Payload("Agent not whitelisted in Admin server"))
	x2 := b2.Next(a2, tool)
	nft2 := t.NFT("both")
	t.wEvidence(wCalls(a2.Sig, tool, t.wCred("session"), wOut("https://"+t.wHost("unknown"), ""))...)
	t.intent(nft2, U, x2, "", "ok")
	threat := false
	for _, r := range t.rows(nft2) {
		if r.From == A && r.To == tool {
			threat = r.Threat
		}
	}
	t.Check(threat, "1001 on the agent's envelope should still mark A→tool a threat")
	t.Equal("threat rows", len(t.threats(nft2)), 1)
	t.wExpect("threat and warning together", nft2, map[pair][]int64{{A, tool}: {5101}})
}

func scWarnDashboard(t *T) {
	A, tool := t.Actor("agent"), t.h.toolDID
	bad, good := t.wHost("bad"), t.wHost("good")
	t.wBase(good, "Trusted")
	key := t.wCred("flagged-key")

	// Evidence first, then flag the key (needs evidence to exist), then the
	// intent arrives and picks up both warnings.
	b := t.Builder("warned")
	U := t.h.user.DID
	a := b.Next(b.Root(U), A)
	x := b.Next(a, tool)
	warned := t.NFT("warned")
	t.wEvidence(wCalls(a.Sig, tool, key, wOut("POST https://"+bad+"/v1/export", key))...)
	t.wSetCredential(key, "flagged")
	t.intent(warned, U, x, "", "ok")
	clean, _ := t.wRun("clean", A, true, wOut("GET https://"+good+"/v1", ""))
	t.wExpect("warned intent", warned, map[pair][]int64{{A, tool}: {5101, 5107}})

	d, err := t.h.Login(t.h.user.Email, t.h.user.Password)
	t.Must(err, "user login")

	// intent-info: per hop and for the whole intent.
	info, err := d.Get("/dashboard/v1/intent-info?intentID=" + warned)
	t.Must(err, "intent-info")
	t.Equal("intent-info warnings", t.wJSONCounts("intent-info", info["warnings"]), map[int64]int{5101: 1, 5107: 1})
	hops, _ := info["interactions"].([]any)
	t.Equal("intent-info hops", len(hops), 3)
	for _, it := range hops {
		m, _ := it.(map[string]any)
		want := []int64{}
		if m["from"] == A && m["to"] == tool {
			want = []int64{5101, 5107}
		}
		t.Equal(fmt.Sprintf("intent-info hop %v→%v warnings", m["from"], m["to"]), t.wJSONCodes("intent-info hop", m["warnings"]), want)
	}
	cleanInfo, err := d.Get("/dashboard/v1/intent-info?intentID=" + clean)
	t.Must(err, "intent-info (clean)")
	t.Equal("clean intent warnings", t.wJSONCodes("clean intent-info", cleanInfo["warnings"]), []int64{})

	// intent-diagram
	diag, err := d.Get("/dashboard/v1/intent-diagram?intentID=" + warned)
	t.Must(err, "intent-diagram")
	basic, _ := diag["basicInfo"].(map[string]any)
	t.Equal("intent-diagram warnings", t.wJSONCounts("intent-diagram", basic["warnings"]), map[int64]int{5101: 1, 5107: 1})

	// intent-list (the user's own list). Earlier scenarios add intents for
	// the same user, so walk the pages until both are found.
	var items []any
	for page := 1; page <= 100; page++ {
		list, err := d.Get(fmt.Sprintf("/dashboard/v1/intent-list?page=%d", page))
		t.Must(err, "intent-list")
		pageItems, _ := list["intentsList"].([]any)
		items = append(items, pageItems...)
		if pages, _ := list["totalPages"].(float64); page >= int(pages) {
			break
		}
	}
	seen := map[string]bool{}
	for _, it := range items {
		m, _ := it.(map[string]any)
		switch m["intentID"] {
		case warned:
			seen[warned] = true
			t.Equal("intent-list warned item", t.wJSONCounts("intent-list", m["warnings"]), map[int64]int{5101: 1, 5107: 1})
		case clean:
			seen[clean] = true
			t.Equal("intent-list clean item", t.wJSONCodes("intent-list clean", m["warnings"]), []int64{})
		}
	}
	t.Check(seen[warned] && seen[clean], "intent-list is missing the scenario's intents (found %v)", seen)

	// agent-info: counts over the hops A initiated.
	ag, err := d.Get("/dashboard/v1/agent-info?agentDID=" + A)
	t.Must(err, "agent-info")
	w, _ := ag["warnings"].(map[string]any)
	total, _ := w["total"].(float64)
	t.Equal("agent-info warnings.total", int(total), 2)
	t.Equal("agent-info warnings.list", t.wJSONCounts("agent-info", w["list"]), map[int64]int{5101: 1, 5107: 1})

	// credential-info: destinations grouped by resource, server_out only
	// (the key also sat on client_out 127.0.0.1 and server_in tool rows).
	cred, err := t.wAdmin().Get("/dashboard/v1/credential-info?credentialID=" + key)
	t.Must(err, "credential-info")
	dests, _ := cred["destinations"].([]any)
	var ids []string
	for _, it := range dests {
		m, _ := it.(map[string]any)
		id, _ := m["resourceID"].(string)
		ids = append(ids, id)
		urls, _ := m["urls"].([]any)
		t.Check(len(urls) > 0, "credential-info destination %s has no urls", id)
		t.Check(m["trustStatus"] != nil, "credential-info destination %s has no trustStatus", id)
	}
	sort.Strings(ids)
	t.Equal("credential-info destinations", ids, []string{bad})
}

func scWarnGrowingIntent(t *T) {
	U, A, B, tool := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.h.toolDID
	safe := t.wHost("safe")
	t.wBase(safe, "Trusted")
	b := t.Builder("main")
	a := b.Next(b.Root(U), A)
	x := b.Next(a, tool)
	nft := t.NFT("intent")
	t.wEvidence(wCalls(a.Sig, tool, t.wCred("session"), wOut("https://"+safe+"/v1", ""))...)
	t.intent(nft, U, x, "", "ok")
	t.wExpect("first txn", nft, map[pair][]int64{{A, tool}: nil})

	// Second txn: the tool hands off to B, and while serving that the tool
	// calls an unknown host. Evidence for it names x's signature.
	y := b.Next(x, B)
	t.wEvidence(wOut("https://"+t.wHost("unknown")+"/hook", "").with("request_id", x.Sig))
	t.intent(nft, U, y, "", "ok")

	codes := t.wCodes(nft)
	for _, r := range t.rows(nft) {
		want := []int64{}
		if r.Sig == x.Sig {
			want = []int64{5101} // every hop carrying the tool's request
		}
		t.Check(reflect.DeepEqual(codes[r.ID], want), "after second txn: hop %s (%s→%s, sig %s) warnings %v, want %v",
			r.ID, shortDID(r.From), shortDID(r.To), r.Sig, codes[r.ID], want)
	}
}

func (e wEv) with(k string, v any) wEv {
	e[k] = v
	return e
}

func scWarnRace(t *T) {
	const n = 16
	U, tool := t.h.user.DID, t.h.toolDID
	type job struct {
		nft      string
		agent    string
		body     []byte
		evidence []wEv
	}
	jobs := make([]job, n)
	for i := range jobs {
		name := fmt.Sprintf("r%02d", i)
		A := t.Actor("agent-" + name)
		b := t.Builder(name)
		a := b.Next(b.Root(U), A)
		x := b.Next(a, tool)
		nft := t.NFT(name)
		t.Track(nft)
		jobs[i] = job{nft, A, TxBody(U, NFT{ID: nft, Data: IntentNFTData(nft, x)}),
			wCalls(a.Sig, tool, t.wCred("session"), wOut("https://"+t.wHost("race-"+name)+"/x", ""))}
	}

	var mu sync.Mutex
	var errs []string
	fail := func(f string, a ...any) { mu.Lock(); errs = append(errs, fmt.Sprintf(f, a...)); mu.Unlock() }
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(2)
		go func() { // the observer reports
			defer wg.Done()
			if i%2 == 0 {
				time.Sleep(time.Duration(i) * time.Millisecond)
			}
			code, body, err := t.h.post("/core/v1/auth-evidence", map[string]string{"X-API-Key": "txnsim-key-" + t.h.tag},
				[]byte(mustJSON(map[string]any{"records": j.evidence})))
			if err != nil || code != http.StatusOK {
				fail("%s evidence: HTTP %d %v %.200s", j.nft, code, err, body)
			}
		}()
		go func() { // the run finishes and its chain lands
			defer wg.Done()
			if i%2 == 1 {
				time.Sleep(time.Duration(i) * time.Millisecond)
			}
			res := t.h.SendTx(j.body, "")
			if res.Err != nil || !res.OK {
				fail("%s tx: HTTP %d %v", j.nft, res.Code, res.Err)
				return
			}
			if code, b, err := t.h.SendSig(res.ReqID, ""); err != nil || code != http.StatusOK {
				fail("%s signature: HTTP %d %v %.200s", j.nft, code, err, b)
			}
		}()
	}
	wg.Wait()
	for _, e := range errs {
		t.Failf("%s", e)
	}
	for _, j := range jobs {
		t.wExpect("race "+j.nft, j.nft, map[pair][]int64{{j.agent, tool}: {5101}})
	}
}
