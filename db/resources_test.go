package db

import (
	"os"
	"reflect"
	"testing"
)

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./db/
func TestResourceGroupingByBase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	d := New(dsn)
	defer d.Close()

	const (
		org  = "resources-test-org"
		host = "restest.example"
	)
	cleanup := func() {
		d.conn.Exec(`DELETE FROM new_interactions WHERE organization_id = $1`, org)
		d.conn.Exec(`DELETE FROM resource_accesses WHERE host = $1`, host)
		d.conn.Exec(`DELETE FROM resource_bases WHERE host = $1`, host)
	}
	cleanup()
	defer cleanup()

	if _, err := d.conn.Exec(`INSERT INTO new_interactions (interaction_id, intent_id, organization_id, signature) VALUES
		('rt-1', 'rt-intent-a', $1, 'rt-sig-1'),
		('rt-2', 'rt-intent-b', $1, 'rt-sig-2'),
		('rt-3', 'rt-intent-a', $1, 'rt-sig-3')`, org); err != nil {
		t.Fatal(err)
	}
	record := func(sig, dest, cred, method string) {
		t.Helper()
		if n, err := d.RecordResourceAccess(sig, dest, cred, method); err != nil || n != 1 {
			t.Fatalf("RecordResourceAccess(%s, %s) = %d, %v", sig, dest, n, err)
		}
	}
	record("rt-sig-1", "https://www.RESTEST.example/jira/ticket1/?token=secret#x", "rt-cred-1", "bearer")
	record("rt-sig-2", "restest.example/jira/ticket2", "", "")
	record("rt-sig-3", "restest.example/jiraextra/1", "rt-cred-2", "apikey")
	record("rt-sig-3", "PUT https://restest.example/confluence/page", "", "")

	get := func(id string) *ResourceSummary {
		t.Helper()
		r, err := d.GetResource(id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// No base yet: everything groups under the host, Unreviewed.
	if r := get(host); r == nil || r.IntentCount != 2 || r.CredentialCount != 2 || r.TrustStatus != ResourceUnreviewed {
		t.Fatalf("before base: %+v", r)
	}

	// Inserted the way the ops script does: any URL form, the trigger normalizes.
	if _, err := d.conn.Exec(`INSERT INTO resource_bases (base_url, name) VALUES ('https://www.restest.example/jira/', 'Test Jira')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`INSERT INTO resource_bases (base_url) VALUES ('https://')`); err == nil {
		t.Fatal("base without a host was accepted")
	}

	// Past accesses regroup at once; /jiraextra is not under /jira.
	jira := get(host + "/jira")
	if jira == nil || jira.Name != "Test Jira" || jira.IntentCount != 2 || jira.CredentialCount != 1 {
		t.Fatalf("jira: %+v", jira)
	}
	if rest := get(host); rest == nil || rest.IntentCount != 1 || rest.CredentialCount != 1 {
		t.Fatalf("host remainder: %+v", rest)
	}

	// The intent page sees each resource with the full URLs it hit (no query).
	res, err := d.GetIntentResources("rt-intent-a")
	if err != nil {
		t.Fatal(err)
	}
	urls := map[string][]string{}
	for _, r := range res {
		urls[r.ID] = r.URLs
	}
	want := map[string][]string{
		host + "/jira": {host + "/jira/ticket1"},
		host:           {host + "/confluence/page", host + "/jiraextra/1"},
	}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("intent resources = %v, want %v", urls, want)
	}

	intents, err := d.GetResourceIntents(host+"/jira", 10, 0)
	if err != nil || len(intents) != 2 {
		t.Fatalf("jira intents = %v, %v", intents, err)
	}
	creds, err := d.GetResourceCredentials(host+"/jira", 10, 0)
	if err != nil || len(creds) != 1 || creds[0].CredentialID != "rt-cred-1" || creds[0].AuthMethod != "bearer" {
		t.Fatalf("jira credentials = %+v, %v", creds, err)
	}

	// Trusting the unmatched host creates a host-level base; /jira keeps its own status.
	if r, err := d.SetResourceTrustStatus(host, ResourceTrusted); err != nil || r == nil || r.TrustStatus != ResourceTrusted {
		t.Fatalf("trust host: %+v, %v", r, err)
	}
	if r := get(host + "/jira"); r.TrustStatus != ResourceUnreviewed || r.IntentCount != 2 {
		t.Fatalf("jira after host trusted: %+v", r)
	}
	if r, err := d.SetResourceTrustStatus(host+"/jira", ResourceFlagged); err != nil || r == nil || r.TrustStatus != ResourceFlagged {
		t.Fatalf("flag jira: %+v, %v", r, err)
	}
	if r, err := d.SetResourceTrustStatus("nothing-here.example", ResourceTrusted); err != nil || r != nil {
		t.Fatalf("unknown resource: %+v, %v", r, err)
	}

	// Re-recording is a no-op.
	record("rt-sig-1", "restest.example/jira/ticket1", "rt-cred-1", "bearer")
	if r := get(host + "/jira"); r.IntentCount != 2 || r.CredentialCount != 1 {
		t.Fatalf("after re-record: %+v", r)
	}
}
