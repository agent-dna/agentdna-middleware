package db

import (
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/lib/pq"
)

// testWarningRules mirrors handler.ComputeWarnings for the rules that read
// database facts (5101, 5105, 5107), so this test checks the facts the SQL
// produces. The handler package tests the rules themselves.
func testWarningRules(facts []WarningFact) []int64 {
	set := map[int64]bool{}
	for _, f := range facts {
		if f.Destination != "" && (f.TrustStatus == "Unreviewed" || f.TrustStatus == "Flagged") {
			set[5101] = true
		}
		if f.CredentialID == "" {
			continue
		}
		if f.CredentialResourceCount > 1 {
			set[5105] = true
		}
		if f.CredentialStatus == "flagged" || f.CredentialStatus == "compromised" {
			set[5107] = true
		}
	}
	out := []int64{}
	for _, c := range []int64{5101, 5105, 5107} {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./db/
func TestRecomputeWarnings(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	d := New(dsn)
	defer d.Close()

	const org = "warnings-test-org"
	cleanup := func() {
		d.conn.Exec(`DELETE FROM new_interactions WHERE organization_id = $1`, org)
		d.conn.Exec(`DELETE FROM auth_evidence WHERE organization_id = $1`, org)
		d.conn.Exec(`DELETE FROM resource_bases WHERE host LIKE 'wtest-%.example'`)
		d.conn.Exec(`DELETE FROM credentials WHERE credential_id LIKE 'wtest-%'`)
	}
	cleanup()
	defer cleanup()

	// w-1 and w-4 share credential c1, which reaches two resources (a, c).
	// w-2 uses c2 on resource b only. w-3 has no evidence.
	// w-1 and w-4 are initiated by agent w-agent.
	if _, err := d.conn.Exec(`INSERT INTO new_interactions (interaction_id, intent_id, organization_id, signature, initiator_did) VALUES
		('w-1', 'w-intent-a', $1, 'w-sig-1', 'w-agent'),
		('w-2', 'w-intent-b', $1, 'w-sig-2', 'w-other'),
		('w-3', 'w-intent-a', $1, 'w-sig-3', 'w-other'),
		('w-4', 'w-intent-c', $1, 'w-sig-4', 'w-agent')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`INSERT INTO auth_evidence (request_id, source, destination, credential_id, organization_id) VALUES
		('w-sig-1', 'server_out', 'GET https://wtest-a.example/x',        'wtest-c1', $1),
		('w-sig-1', 'server_out', 'POST https://www.wtest-a.example/x/',  'wtest-c1', $1),
		('w-sig-1', 'server_in',  '',                                     'wtest-c1', $1),
		('w-sig-2', 'server_out', 'POST https://wtest-b.example/y',       'wtest-c2', $1),
		('w-sig-4', 'server_out', 'GET https://wtest-c.example/z',        'wtest-c1', $1),
		-- Not called services: server_in names the server's own DID and
		-- client_out the local hop. Neither may count as a destination.
		('w-sig-1', 'client_out', '127.0.0.1',                            'wtest-c1', $1),
		('w-sig-3', 'server_in',  'bafywtestserverdid',                   'wtest-c3', $1),
		('w-sig-3', 'client_out', '127.0.0.1',                            'wtest-c3', $1)`, org); err != nil {
		t.Fatal(err)
	}

	codes := func(id string) []int64 {
		t.Helper()
		var got []int64
		if err := d.conn.QueryRow(`SELECT warning_codes FROM new_interactions WHERE interaction_id = $1`, id).Scan(pq.Array(&got)); err != nil {
			t.Fatal(err)
		}
		if got == nil {
			got = []int64{}
		}
		return got
	}
	expect := func(step string, want map[string][]int64) {
		t.Helper()
		for id, w := range want {
			if got := codes(id); !reflect.DeepEqual(got, w) {
				t.Errorf("%s: %s warning_codes = %v, want %v", step, id, got, w)
			}
		}
	}
	recompute := func(sigs []string, resourceID, credentialID string) int {
		t.Helper()
		n, err := d.RecomputeWarnings(sigs, resourceID, credentialID, testWarningRules)
		if err != nil {
			t.Fatalf("RecomputeWarnings: %v", err)
		}
		return n
	}

	// 1. Intent arrives with w-sig-1: w-4 is pulled in through the shared credential.
	if n := recompute([]string{"w-sig-1"}, "", ""); n != 2 {
		t.Errorf("step 1 changed %d, want 2", n)
	}
	expect("step 1", map[string][]int64{
		"w-1": {5101, 5105}, "w-4": {5101, 5105}, "w-2": {}, "w-3": {},
	})

	// 2. Admin trusts resource a: w-1 loses 5101, w-4 still calls untrusted c.
	if _, err := d.conn.Exec(`INSERT INTO resource_bases (base_url, trust_status) VALUES ('wtest-a.example', 'Trusted')`); err != nil {
		t.Fatal(err)
	}
	recompute(nil, "wtest-a.example", "")
	expect("step 2", map[string][]int64{"w-1": {5105}, "w-4": {5101, 5105}})

	// 3. Admin marks c1 compromised: both its interactions gain 5107, w-2 untouched.
	if _, err := d.conn.Exec(`INSERT INTO credentials (credential_id, status) VALUES ('wtest-c1', 'compromised')`); err != nil {
		t.Fatal(err)
	}
	recompute(nil, "", "wtest-c1")
	expect("step 3", map[string][]int64{"w-1": {5105, 5107}, "w-4": {5101, 5105, 5107}, "w-2": {}})

	// 4. Back to active: 5107 is cleared again.
	if _, err := d.conn.Exec(`UPDATE credentials SET status = 'active' WHERE credential_id = 'wtest-c1'`); err != nil {
		t.Fatal(err)
	}
	recompute(nil, "", "wtest-c1")
	expect("step 4", map[string][]int64{"w-1": {5105}, "w-4": {5101, 5105}})

	// 5. Evidence for a request whose interaction has not landed: nothing to do.
	if n := recompute([]string{"w-sig-missing"}, "", ""); n != 0 {
		t.Errorf("step 5 changed %d, want 0", n)
	}

	// 6. w-2 on its own: 5101 for untrusted b, no 5105 (c2 reaches one resource).
	recompute([]string{"w-sig-2"}, "", "")
	expect("step 6", map[string][]int64{"w-2": {5101}, "w-3": {}})

	// 7. Recomputing again changes nothing.
	if n := recompute([]string{"w-sig-1", "w-sig-2", "w-sig-3"}, "", ""); n != 0 {
		t.Errorf("step 7 changed %d, want 0", n)
	}

	// 8. Concurrent recomputes serialize on the lock instead of failing.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.RecomputeWarnings([]string{"w-sig-1", "w-sig-2"}, "wtest-a.example", "wtest-c1", testWarningRules); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent RecomputeWarnings: %v", err)
	}
	expect("step 8", map[string][]int64{"w-1": {5105}, "w-2": {5101}, "w-4": {5101, 5105}})

	// Counts per intent (w-intent-a holds w-1 and the warning-free w-3) and
	// per initiating agent.
	byIntent, err := d.GetWarningCountsByIntent([]string{"w-intent-a", "w-intent-b", "w-intent-c", "w-intent-none"})
	if err != nil {
		t.Fatal(err)
	}
	wantByIntent := map[string][]WarningCount{
		"w-intent-a": {{5105, 1}},
		"w-intent-b": {{5101, 1}},
		"w-intent-c": {{5101, 1}, {5105, 1}},
	}
	if !reflect.DeepEqual(byIntent, wantByIntent) {
		t.Errorf("GetWarningCountsByIntent = %v, want %v", byIntent, wantByIntent)
	}
	byAgent, err := d.GetWarningCountsByInitiator("w-agent")
	if err != nil {
		t.Fatal(err)
	}
	if want := []WarningCount{{5101, 1}, {5105, 2}}; !reflect.DeepEqual(byAgent, want) {
		t.Errorf("GetWarningCountsByInitiator = %v, want %v", byAgent, want)
	}
	if none, err := d.GetWarningCountsByInitiator("w-nobody"); err != nil || len(none) != 0 {
		t.Errorf("GetWarningCountsByInitiator(unknown) = %v, %v; want empty", none, err)
	}

	// The credential destination list groups by resource the same way:
	// both spellings of a/x are one resource, c is the second.
	dests, err := d.GetCredentialDestinations("wtest-c1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	urls := 0
	for _, r := range dests {
		got[r.ResourceID] = r.TrustStatus
		urls += len(r.URLs)
	}
	want := map[string]string{"wtest-a.example": "Trusted", "wtest-c.example": "Unreviewed"}
	if !reflect.DeepEqual(got, want) || urls != 3 {
		t.Errorf("GetCredentialDestinations = %v (%d urls), want %v (3 urls)", got, urls, want)
	}
}
