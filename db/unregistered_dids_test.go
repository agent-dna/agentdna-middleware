package db

import (
	"os"
	"reflect"
	"testing"
)

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./db/
func TestUnregisteredDIDsAcceptsEveryRegisteredDID(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	d := New(dsn)
	defer d.Close()

	const email, apiKey = "multi-did@test.local", "test-key-multi-did"
	cleanup := func() {
		d.conn.Exec(`DELETE FROM user_dids WHERE email = $1`, email)
		d.conn.Exec(`DELETE FROM new_org_users WHERE email = $1`, email)
		d.conn.Exec(`DELETE FROM new_tools WHERE did = 'tool-did'`)
		d.conn.Exec(`DELETE FROM new_admins WHERE did = 'admin-did'`)
	}
	cleanup()
	defer cleanup()

	if _, err := d.conn.Exec(`INSERT INTO new_org_users (email, api_key) VALUES ($1, $2)`, email, apiKey); err != nil {
		t.Fatal(err)
	}
	for _, did := range []string{"old-did", "new-did"} {
		if err := d.AddUserDIDByAPIKey(apiKey, did); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.StoreNewTool("tool-did", "tool", "org"); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureAdmin("admin-did", "org", "admin-key", "admin"); err != nil {
		t.Fatal(err)
	}

	got, err := d.UnregisteredDIDs([]string{"old-did", "stranger-1", "new-did", "tool-did", "admin-did", "stranger-2"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"stranger-1", "stranger-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnregisteredDIDs = %v, want %v", got, want)
	}
}
