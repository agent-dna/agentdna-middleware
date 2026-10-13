package db

import (
	"os"
	"reflect"
	"testing"
)

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./db/
func TestAdminDetailGroupsDIDsByUsername(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	d := New(dsn)
	defer d.Close()

	const org = "admin-detail-org"
	cleanup := func() {
		d.conn.Exec(`DELETE FROM new_admins WHERE organization_id LIKE $1 || '%'`, org)
		d.conn.Exec(`DELETE FROM new_intents WHERE organization_id = $1`, org)
		d.conn.Exec(`DELETE FROM new_interactions WHERE organization_id = $1`, org)
	}
	cleanup()
	defer cleanup()

	for _, stmt := range []string{
		`INSERT INTO new_admins (did, organization_id, name, email, created_at) VALUES
			('admin-old', $1, 'alice', 'alice@test.local', NOW() - INTERVAL '2 days'),
			('admin-new', $1 || '-other', 'alice', '',     NOW() - INTERVAL '1 day'),
			('admin-bob', $1, 'bob',   'bob@test.local',   NOW())`,
		`INSERT INTO new_intents (intent_id, initiator_did, organization_id) VALUES
			('intent-old', 'admin-old', $1), ('intent-bob', 'admin-bob', $1)`,
		`INSERT INTO new_interactions (interaction_id, initiator_did, intent_id, organization_id, threat) VALUES
			('ix-old', 'admin-old', 'intent-old', $1, 1), ('ix-bob', 'admin-bob', 'intent-bob', $1, 0)`,
	} {
		if _, err := d.conn.Exec(stmt, org); err != nil {
			t.Fatal(err)
		}
	}

	r, err := d.GetAdminDetail("admin-old")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"admin-old", "admin-new"}; !reflect.DeepEqual(r.DIDs, want) {
		t.Errorf("DIDs = %v, want %v", r.DIDs, want)
	}
	if r.UserDID != "admin-new" {
		t.Errorf("UserDID = %q, want the newest DID admin-new", r.UserDID)
	}
	if r.UserName != "alice@test.local" || r.DisplayName != "alice" {
		t.Errorf("UserName/DisplayName = %q/%q", r.UserName, r.DisplayName)
	}
	if r.TotalInteractions != 1 || r.TotalThreats != 1 || r.TotalIntents != 1 {
		t.Errorf("totals = %d/%d/%d, want 1/1/1", r.TotalInteractions, r.TotalThreats, r.TotalIntents)
	}

	// Looked up by the newer DID, the older DID's activity still counts, and
	// an empty org lists it across every org.
	n, err := d.CountInteractionsByUser("admin-new", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("CountInteractionsByUser(admin-new) = %d, want 1", n)
	}

	if _, err := d.GetAdminDetail("no-such-admin"); err == nil {
		t.Error("GetAdminDetail found an unknown DID")
	}

	// Rows with no organization_id (as the session middleware accepts) still
	// resolve and group.
	if _, err := d.conn.Exec(`INSERT INTO new_admins (did, organization_id, name) VALUES
		('admin-noorg-1', NULL, 'carol'), ('admin-noorg-2', NULL, 'carol')`); err != nil {
		t.Fatal(err)
	}
	defer d.conn.Exec(`DELETE FROM new_admins WHERE name = 'carol'`)
	r, err = d.GetAdminDetail("admin-noorg-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.DIDs) != 2 {
		t.Errorf("no-org DIDs = %v, want both carol rows", r.DIDs)
	}
}
