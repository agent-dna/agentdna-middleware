// Command seedwarnings loads demo data for the 51xx warnings into the local
// database (DATABASE_URL from .env), then computes the warnings with the same
// code the server uses and checks each interaction got the codes expected.
//
//	go run ./cmd/seedwarnings          # (re)seed: removes old seed rows first
//	go run ./cmd/seedwarnings -clean   # only remove seed rows
//
// Every row it writes is marked: ids start with "seedw-", resource hosts end
// in ".seedw.test". Nothing else in the database is touched.
//
// Covered: each rule (5101, 5105, 5107, 5108), several warnings on one
// interaction and on one intent, a transaction threat next to a warning,
// path-prefix trust, server_in/client_out rows that must not count, NULL and
// empty evidence fields, odd destination spellings, evidence for requests
// with no interaction, one signature in two intents, an interaction with no
// signature, stale codes being cleared, and an agent with no warnings.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/handler"

	_ "github.com/joho/godotenv/autoload"
	"github.com/lib/pq"
)

const (
	agentA = "seedw-agent-a"
	agentB = "seedw-agent-b"
	agentC = "seedw-agent-c"
	toolX  = "seedw-tool-billing"
	toolY  = "seedw-tool-docs"
)

var (
	orgID  = flag.String("org", os.Getenv("ORG_ID"), "organization the seed data belongs to")
	user1  = flag.String("user", "bafybmimockseed10091208newdid", "DID of the user who starts most intents")
	user2  = flag.String("user2", "QmSt1gPztoVVG5pTWQrpPAsCFxAQAPJTU26xDpU8pvkHXd", "DID of a second user")
	clean  = flag.Bool("clean", false, "only remove seed rows")
	nowRef = time.Now().UTC().Truncate(time.Second)
)

func str(s string) *string { return &s }

// interaction is one hop. sig "" leaves the signature empty.
type interaction struct {
	n             int
	from, to, typ string
	sig           string
	at            time.Time
	message       *string // nil writes NULL
	nullFromName  bool    // write initiator_name as NULL
	threatCode    int     // a transaction threat (stored in threats)
	staleCodes    string  // warning_codes before the recompute, e.g. "{5106}"
}

// evidence is one auth_evidence row. nil pointers write NULL.
type evidence struct {
	req, source, dest      string
	method, cred, identity *string
	status                 string
	observed               *time.Time
}

type intent struct {
	id, initiator, initiatorName, status, review string
	ended                                        bool
	hops                                         []interaction
}

func main() {
	flag.Parse()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is not set (run from the repo root so .env is read)")
	}
	if *orgID == "" {
		log.Fatal("no org: set ORG_ID or pass -org")
	}

	// db.New runs the migrations, so warning_codes and resource_for_url exist
	// even before the server has been started on the new code.
	d := db.New(dsn)
	defer d.Close()
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if err := removeSeed(conn); err != nil {
		log.Fatalf("clean: %v", err)
	}
	log.Printf("removed old seed rows")
	if *clean {
		return
	}

	intents, ev := buildSeed()
	if err := insertSeed(conn, intents, ev); err != nil {
		log.Fatalf("insert: %v", err)
	}

	var sigs []string
	seen := map[string]bool{}
	for _, in := range intents {
		for _, h := range in.hops {
			if h.sig != "" && !seen[h.sig] {
				seen[h.sig] = true
				sigs = append(sigs, h.sig)
			}
		}
	}
	for _, s := range sigs {
		if _, err := d.RecordResourcesForRequest(s); err != nil {
			log.Fatalf("record resources %s: %v", s, err)
		}
	}

	maxAge, err := handler.ParseCredentialMaxAge(os.Getenv("DURATION_CREDENTIAL"))
	if err != nil {
		log.Fatal(err)
	}
	if maxAge == 0 {
		log.Printf("WARNING: DURATION_CREDENTIAL is unset, so 5108 is off here and in the server")
	}
	n, err := d.RecomputeWarnings(sigs, "", "", func(f []db.WarningFact) []int64 {
		return handler.ComputeWarnings(f, maxAge)
	})
	if err != nil {
		log.Fatalf("recompute: %v", err)
	}
	log.Printf("seeded %d intents, %d evidence rows; warnings changed on %d interactions", len(intents), len(ev), n)

	if !verify(conn, intents, maxAge > 0) {
		os.Exit(1)
	}
}

func buildSeed() ([]intent, []evidence) {
	at := func(minsAgo int) time.Time { return nowRef.Add(-time.Duration(minsAgo) * time.Minute) }
	sec := func(t time.Time, s int) *time.Time { u := t.Add(time.Duration(s) * time.Second); return &u }

	// chain builds user -> agent -> tool -> agent -> user, plus extra hops.
	chain := func(id string, user, agent, tool string, start time.Time, extra ...interaction) []interaction {
		hops := []interaction{
			{n: 1, from: user, to: agent, typ: "trigger", at: start, message: str("Run the monthly billing check")},
			{n: 2, from: agent, to: tool, typ: "request", at: start.Add(1 * time.Second), message: str(`{"tool":"fetch","args":{}}`)},
			{n: 3, from: tool, to: agent, typ: "response", at: start.Add(3 * time.Second), message: str(`{"status":"success"}`)},
			{n: 4, from: agent, to: user, typ: "response", at: start.Add(4 * time.Second), message: str("Done.")},
		}
		hops = append(hops, extra...)
		for i := range hops {
			if hops[i].sig == "" && hops[i].n > 0 {
				hops[i].sig = fmt.Sprintf("seedw-sig-%s-%d", strings.TrimPrefix(id, "seedw-intent-"), hops[i].n)
			}
		}
		return hops
	}
	// Every request hop is also seen by the agent's client (client_out,
	// 127.0.0.1) and the tool's server (server_in, the tool's DID), with the
	// agent's session credential. Neither may count as a destination.
	var ev []evidence
	plumbing := func(sig, tool string, t time.Time) {
		ev = append(ev,
			evidence{req: sig, source: "client_out", dest: "127.0.0.1", method: str("bearer_opaque"), cred: str("seedw-cred-session"), status: "accepted", observed: sec(t, 0)},
			evidence{req: sig, source: "server_in", dest: tool, method: str("bearer_opaque"), cred: str("seedw-cred-session"), status: "unknown", observed: sec(t, 0)},
		)
	}
	out := func(sig, dest, method string, cred *string, t time.Time) {
		ev = append(ev, evidence{req: sig, source: "server_out", dest: dest, method: str(method), cred: cred, identity: str("svc-" + method), status: "accepted", observed: sec(t, 1)})
	}

	var intents []intent
	add := func(in intent) { intents = append(intents, in) }

	// 01: clean. Trusted destination, healthy credential, agent C. No warnings.
	t := at(60 * 50)
	h := chain("seedw-intent-01-clean", *user1, agentC, toolX, t)
	plumbing(h[1].sig, toolX, t)
	out(h[1].sig, "GET https://api.trusted.seedw.test/v1/invoices", "api_key", str("seedw-cred-clean"), t)
	add(intent{id: "seedw-intent-01-clean", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Acknowledged", ended: true, hops: h})

	// 02: untrusted destinations on two hops: a host with no base (defaults to
	// Unreviewed) and an explicitly Unreviewed one. 5101 x2 on the intent.
	t = at(60 * 44)
	h = chain("seedw-intent-02-untrusted", *user1, agentA, toolX, t,
		interaction{n: 5, from: agentA, to: toolY, typ: "request", at: t.Add(2 * time.Second), message: str(`{"tool":"lookup"}`)})
	plumbing(h[1].sig, toolX, t)
	plumbing(h[4].sig, toolY, t)
	out(h[1].sig, "POST https://new-host.seedw.test/collect", "none", str(""), t)
	out(h[4].sig, "GET https://api.unrev.seedw.test/v2/lookup", "none", str(""), t)
	add(intent{id: "seedw-intent-02-untrusted", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// 03: one key on two resources (5105 on both hops); the second is under a
	// Flagged path prefix of an otherwise Trusted host (5101 too).
	t = at(60 * 38)
	h = chain("seedw-intent-03-shared-key", *user1, agentA, toolX, t,
		interaction{n: 5, from: agentA, to: toolY, typ: "request", at: t.Add(2 * time.Second), message: str(`{"tool":"docs"}`)})
	plumbing(h[1].sig, toolX, t)
	plumbing(h[4].sig, toolY, t)
	out(h[1].sig, "GET https://api.trusted.seedw.test/v1/accounts", "bearer_jwt", str("seedw-cred-shared"), t)
	out(h[4].sig, "GET https://docs.seedw.test/private/payroll.pdf", "bearer_jwt", str("seedw-cred-shared"), t)
	add(intent{id: "seedw-intent-03-shared-key", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// 04: flagged and compromised credentials (5107); the second hop also
	// calls an unknown host on the same request (5101 + 5107 on one hop).
	t = at(60 * 30)
	h = chain("seedw-intent-04-bad-creds", *user1, agentB, toolX, t,
		interaction{n: 5, from: agentB, to: toolY, typ: "request", at: t.Add(2 * time.Second), message: str(`{"tool":"sync"}`)})
	plumbing(h[1].sig, toolX, t)
	plumbing(h[4].sig, toolY, t)
	out(h[1].sig, "GET https://api.trusted.seedw.test/v1/me", "basic", str("seedw-cred-flagged"), t)
	out(h[4].sig, "PUT https://api.trusted.seedw.test/v1/sync", "api_key", str("seedw-cred-compromised"), t)
	out(h[4].sig, "POST https://new-host.seedw.test/beacon", "none", str(""), t)
	add(intent{id: "seedw-intent-04-bad-creds", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Flagged", ended: true, hops: h})

	// 05: all four on one hop. seedw-cred-old is compromised, was first seen
	// 200 days ago (an orphan row below) and has reached two resources.
	t = at(60 * 24)
	h = chain("seedw-intent-05-all-four", *user1, agentB, toolX, t)
	plumbing(h[1].sig, toolX, t)
	out(h[1].sig, "POST https://new-host.seedw.test/upload", "api_key", str("seedw-cred-old"), t)
	add(intent{id: "seedw-intent-05-all-four", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// 06: a transaction threat (3303) on the same hop as a warning (5101).
	t = at(60 * 18)
	h = chain("seedw-intent-06-threat-and-warning", *user1, agentA, toolX, t)
	h[1].threatCode = 3303
	plumbing(h[1].sig, toolX, t)
	out(h[1].sig, "DELETE https://api.flagged.seedw.test/v1/records/42", "bearer_jwt", str("seedw-cred-threat"), t)
	add(intent{id: "seedw-intent-06-threat-and-warning", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// 07: messy input from the second user. NULL message and initiator name,
	// NULL credential / identity / auth method / observed_at, an empty
	// destination, odd spellings (case, www., :443, query, fragment,
	// userinfo, bare host), a non-URL and a long unicode URL.
	t = at(60 * 12)
	h = chain("seedw-intent-07-messy-input", *user2, agentA, toolX, t)
	h[0].message = nil
	h[3].nullFromName = true
	plumbing(h[1].sig, toolX, t)
	ev = append(ev,
		evidence{req: h[1].sig, source: "server_out", dest: "POST https://WWW.Api.Unrev.SeedW.test:443/v1/x/?q=1#frag", status: "unknown"},
		evidence{req: h[1].sig, source: "server_out", dest: "api.trusted.seedw.test", method: str("bearer_opaque"), cred: str("seedw-cred-nullobs"), status: "accepted"},
		evidence{req: h[1].sig, source: "server_out", dest: "https://svc:hunter2@API.TRUSTED.seedw.test/a", method: str("basic"), cred: str("seedw-cred-nullobs"), status: "accepted"},
		evidence{req: h[1].sig, source: "server_out", dest: "", method: str("none"), cred: str(""), status: "accepted", observed: sec(t, 1)},
		evidence{req: h[2].sig, source: "server_out", dest: "not a url at all", method: str(""), cred: str(""), status: "rejected", observed: sec(t, 3)},
		evidence{req: h[2].sig, source: "server_out", dest: "GET https://bücher.seedw.test/" + strings.Repeat("katalog/", 60) + "end", method: str("none"), cred: str(""), status: "accepted", observed: sec(t, 3)},
	)
	add(intent{id: "seedw-intent-07-messy-input", initiator: *user2, initiatorName: "SeedUser", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// 08: still running, and its request hop has no signature, so its
	// evidence (written against the request id) can never match it.
	t = at(25)
	h = chain("seedw-intent-08-running-no-signature", *user1, agentC, toolX, t)[:2]
	h[1].sig = ""
	ev = append(ev, evidence{req: "seedw-sig-08-unmatched", source: "server_out", dest: "https://api.flagged.seedw.test/never-matched", method: str("api_key"), cred: str(""), status: "accepted", observed: sec(t, 1)})
	add(intent{id: "seedw-intent-08-running-no-signature", initiator: *user1, initiatorName: "AdityaSoni", status: "running", review: "Unreviewed", ended: false, hops: h})

	// 09a/09b: the same signed request stored under two intents. Both copies
	// get the same warnings.
	for i, suffix := range []string{"09a-dup-signature", "09b-dup-signature"} {
		t = at(60*8 - i*30)
		id := "seedw-intent-" + suffix
		h = chain(id, *user1, agentA, toolX, t)
		h[1].sig = "seedw-sig-09-shared"
		add(intent{id: id, initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Unreviewed", ended: true, hops: h})
	}
	plumbing("seedw-sig-09-shared", toolX, at(60*8))
	out("seedw-sig-09-shared", "GET https://api.flagged.seedw.test/v1/export", "none", str(""), at(60*8))

	// 10: no evidence at all, and a stale warning code left on a hop: the
	// recompute must clear it.
	t = at(60 * 4)
	h = chain("seedw-intent-10-no-evidence", *user1, agentC, toolY, t)
	h[1].staleCodes = "{5106}"
	add(intent{id: "seedw-intent-10-no-evidence", initiator: *user1, initiatorName: "AdityaSoni", status: "completed", review: "Acknowledged", ended: true, hops: h})

	// 11: path-prefix trust the other way: docs.seedw.test is Trusted and only
	// /private is Flagged, so /public is fine. No warnings.
	t = at(60 * 2)
	h = chain("seedw-intent-11-trusted-prefix", *user2, agentC, toolY, t)
	plumbing(h[1].sig, toolY, t)
	out(h[1].sig, "GET https://docs.seedw.test/public/handbook", "api_key", str("seedw-cred-docs"), t)
	out(h[1].sig, "GET https://docs.seedw.test/privateer/notes", "api_key", str("seedw-cred-docs"), t)
	add(intent{id: "seedw-intent-11-trusted-prefix", initiator: *user2, initiatorName: "SeedUser", status: "completed", review: "Unreviewed", ended: true, hops: h})

	// Orphans: evidence whose request never landed as an interaction.
	old := nowRef.AddDate(0, 0, -200)
	ev = append(ev,
		evidence{req: "seedw-sig-orphan-old", source: "server_out", dest: "GET https://api.trusted.seedw.test/v1/legacy", method: str("api_key"), cred: str("seedw-cred-old"), status: "accepted", observed: &old},
		evidence{req: "seedw-sig-orphan-null", source: "server_out", dest: "https://new-host.seedw.test/x", status: "unknown"},
	)
	return intents, ev
}

// expected warning codes per interaction id; anything not listed expects none.
// 5105 (shared key) is disabled for now, so intent 03 only keeps 5101 and
// intent 05 has three of its four codes.
var expected = map[string][]int64{
	"seedw-intent-02-untrusted-2":          {5101},
	"seedw-intent-02-untrusted-5":          {5101},
	"seedw-intent-03-shared-key-5":         {5101},
	"seedw-intent-04-bad-creds-2":          {5107},
	"seedw-intent-04-bad-creds-5":          {5101, 5107},
	"seedw-intent-05-all-four-2":           {5101, 5107, 5108},
	"seedw-intent-06-threat-and-warning-2": {5101},
	"seedw-intent-07-messy-input-2":        {5101},
	"seedw-intent-07-messy-input-3":        {5101},
	"seedw-intent-09a-dup-signature-2":     {5101},
	"seedw-intent-09b-dup-signature-2":     {5101},
}

func insertSeed(conn *sql.DB, intents []intent, ev []evidence) error {
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) {
		if err == nil {
			_, err = tx.Exec(q, args...)
			if err != nil {
				err = fmt.Errorf("%w\n  in: %s", err, strings.TrimSpace(strings.SplitN(q, "\n", 2)[0]))
			}
		}
	}

	for _, a := range []struct{ did, name string }{
		{agentA, "Seed Warn Agent A"}, {agentB, "Seed Warn Agent B"}, {agentC, "Seed Clean Agent C"},
	} {
		exec(`INSERT INTO new_agents (did, name, deployer_did, organization_id, policy, created_at) VALUES ($1, $2, $3, $4, '', $5)`,
			a.did, a.name, *user1, *orgID, nowRef.AddDate(0, 0, -7))
	}
	exec(`INSERT INTO new_tools (did, name, organization_id, agents_list) VALUES
		($1, 'Seed Billing MCP', $3, '["seedw-agent-a","seedw-agent-b","seedw-agent-c"]'),
		($2, 'Seed Docs MCP',    $3, '["seedw-agent-a","seedw-agent-b","seedw-agent-c"]')`, toolX, toolY, *orgID)

	exec(`INSERT INTO resource_bases (base_url, name, trust_status) VALUES
		('api.trusted.seedw.test',   'Seed Trusted API',   'Trusted'),
		('api.flagged.seedw.test',   'Seed Flagged API',   'Flagged'),
		('api.unrev.seedw.test',     'Seed Unreviewed API','Unreviewed'),
		('docs.seedw.test',          'Seed Docs',          'Trusted'),
		('docs.seedw.test/private',  'Seed Docs (private)','Flagged')`)
	exec(`INSERT INTO credentials (credential_id, status, reason, updated_by) VALUES
		('seedw-cred-shared',      'active',      'reviewed, fine',          'seed'),
		('seedw-cred-flagged',     'flagged',     'odd usage pattern',       'seed'),
		('seedw-cred-compromised', 'compromised', 'leaked in a public repo', 'seed'),
		('seedw-cred-old',         'compromised', 'never rotated, leaked',   'seed')`)

	names := map[string]string{
		*user1: "AdityaSoni", *user2: "SeedUser", agentA: "Seed Warn Agent A", agentB: "Seed Warn Agent B",
		agentC: "Seed Clean Agent C", toolX: "Seed Billing MCP", toolY: "Seed Docs MCP",
	}
	for _, in := range intents {
		var ids []string
		threat := 0
		start, end := in.hops[0].at, in.hops[0].at
		for _, h := range in.hops {
			id := fmt.Sprintf("%s-%d", in.id, h.n)
			ids = append(ids, id)
			if h.at.After(end) {
				end = h.at
			}
			var fromName any = names[h.from]
			if h.nullFromName {
				fromName = nil
			}
			threatID := ""
			if h.threatCode != 0 {
				threat = 1
				threatID = in.id + "-threat-" + h.sig
				exec(`INSERT INTO threats (id, intent_id, interaction_id, time, threat_code, message) VALUES ($1, $2, $3, $4, $5, $6)`,
					threatID, in.id, in.id+"-block-"+h.sig, h.at, h.threatCode, "Policy contradiction: deleting records is not allowed")
			}
			stale := h.staleCodes
			if stale == "" {
				stale = "{}"
			}
			exec(`INSERT INTO new_interactions (interaction_id, initiator_did, initiator_name, interacted_to_did, interacted_to_name,
				type, direction, threat, intent_id, organization_id, message, signature, hash, threat_id, time, warning_codes)
				VALUES ($1, $2, $3, $4, $5, $6, '', $7, $8, $9, $10, $11, $12, $13, $14, $15::int[])`,
				id, h.from, fromName, h.to, names[h.to], h.typ, boolInt(h.threatCode != 0), in.id, *orgID,
				sqlStr(h.message), h.sig, "seedw-hash-"+id, threatID, h.at, stale)
		}
		idsJSON := `["` + strings.Join(ids, `","`) + `"]`
		var ended any
		if in.ended {
			ended = end
		}
		exec(`INSERT INTO new_intents (intent_id, interaction_ids, initiator_did, initiator_name, organization_id, started_at, ended_at,
			status, threat_detected, flow_type, executor, chain_depth, review_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'delegated', $3, $10, $11)`,
			in.id, idsJSON, in.initiator, in.initiatorName, *orgID, start, ended, in.status, threat, len(in.hops), in.review)
	}

	for _, e := range ev {
		var observed any
		if e.observed != nil {
			observed = *e.observed
		}
		exec(`INSERT INTO auth_evidence (request_id, source, run_id, auth_method, credential_id, identity_id, identity_name,
			auth_status, key_version, destination, organization_id, observed_at)
			VALUES ($1, $2, 'seedw-run', $3, $4, $5, NULL, $6, 'seedw-kv1', $7, $8, $9)
			ON CONFLICT DO NOTHING`,
			e.req, e.source, sqlStr(e.method), sqlStr(e.cred), sqlStr(e.identity), e.status, e.dest, *orgID, observed)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func removeSeed(conn *sql.DB) error {
	for _, q := range []string{
		`DELETE FROM new_interactions WHERE interaction_id LIKE 'seedw-%'`,
		`DELETE FROM new_intents      WHERE intent_id      LIKE 'seedw-%'`,
		`DELETE FROM threats          WHERE id             LIKE 'seedw-%'`,
		`DELETE FROM auth_evidence    WHERE request_id     LIKE 'seedw-%'`,
		`DELETE FROM resource_accesses WHERE intent_id     LIKE 'seedw-%'`,
		`DELETE FROM resource_bases   WHERE host LIKE '%seedw.test'`,
		`DELETE FROM credentials      WHERE credential_id  LIKE 'seedw-%'`,
		`DELETE FROM new_agents       WHERE did            LIKE 'seedw-%'`,
		`DELETE FROM new_tools        WHERE did            LIKE 'seedw-%'`,
	} {
		if _, err := conn.Exec(q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	return nil
}

func verify(conn *sql.DB, intents []intent, with5108 bool) bool {
	rows, err := conn.Query(`SELECT interaction_id, warning_codes FROM new_interactions WHERE interaction_id LIKE 'seedw-%'`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	got := map[string][]int64{}
	for rows.Next() {
		var id string
		var codes []int64
		if err := rows.Scan(&id, pq.Array(&codes)); err != nil {
			log.Fatal(err)
		}
		got[id] = codes
	}

	ok := true
	ids := make([]string, 0, len(got))
	for id := range got {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Println()
	fmt.Println("interaction                                   warnings")
	fmt.Println("--------------------------------------------  ------------------------")
	for _, id := range ids {
		want := expected[id]
		if !with5108 {
			want = without(want, 5108)
		}
		have := got[id]
		mark := "ok"
		if !reflect.DeepEqual(norm(have), norm(want)) {
			mark = fmt.Sprintf("MISMATCH, want %v", norm(want))
			ok = false
		}
		if len(have) > 0 || mark != "ok" {
			fmt.Printf("%-44s  %-24s %s\n", id, fmt.Sprint(norm(have)), mark)
		}
	}
	fmt.Printf("\n%d seeded interactions checked; ones not listed have no warnings, as expected.\n", len(ids))
	if ok {
		fmt.Println("All warnings match the expected codes.")
	}
	return ok
}

func norm(c []int64) []int64 {
	if c == nil {
		return []int64{}
	}
	return c
}

func without(c []int64, drop int64) []int64 {
	out := []int64{}
	for _, x := range c {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

func sqlStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
