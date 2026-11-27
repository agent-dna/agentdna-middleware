package db

import (
	"os"
	"testing"
)

// Needs a disposable Postgres: TEST_DATABASE_URL=postgres://... go test ./db/
func TestFlagCredentialOnRejections(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	d := New(dsn)
	defer d.Close()

	const org = "autoflag-test-org"
	cleanup := func() {
		d.conn.Exec(`DELETE FROM auth_evidence WHERE organization_id = $1`, org)
		d.conn.Exec(`DELETE FROM credentials WHERE credential_id LIKE 'aftest-%'`)
	}
	cleanup()
	defer cleanup()

	evidence := func(req, source, cred, status string) {
		t.Helper()
		if _, err := d.conn.Exec(`INSERT INTO auth_evidence (request_id, source, destination, credential_id, auth_status, organization_id)
			VALUES ($1, $2, '', $3, $4, $5)`, req, source, cred, status, org); err != nil {
			t.Fatal(err)
		}
	}
	check := func(step, cred string, wantFlagged bool, wantCount int, wantStatus string) {
		t.Helper()
		flagged, n, err := d.FlagCredentialOnRejections(cred, 2)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if flagged != wantFlagged || n != wantCount {
			t.Errorf("%s: flagged=%v rejections=%d, want flagged=%v rejections=%d", step, flagged, n, wantFlagged, wantCount)
		}
		status, by := "active", ""
		d.conn.QueryRow(`SELECT status, updated_by FROM credentials WHERE credential_id = $1`, cred).Scan(&status, &by)
		if status != wantStatus {
			t.Errorf("%s: status=%q, want %q", step, status, wantStatus)
		}
		if wantFlagged && by != AutoFlaggedBy {
			t.Errorf("%s: updated_by=%q, want %q", step, by, AutoFlaggedBy)
		}
	}

	// 1. Two rejected requests (r2 seen by two sources, counted once) and an
	//    accepted one: 2 is not more than the limit of 2.
	evidence("aftest-r1", "server_in", "aftest-key", "rejected")
	evidence("aftest-r2", "server_in", "aftest-key", "rejected")
	evidence("aftest-r2", "gateway", "aftest-key", " Rejected ")
	evidence("aftest-r3", "server_in", "aftest-key", "accepted")
	check("at the limit", "aftest-key", false, 2, "active")

	// 2. A third rejection goes over it: the key is flagged.
	evidence("aftest-r4", "server_in", "aftest-key", "rejected")
	check("over the limit", "aftest-key", true, 3, "flagged")

	// 3. Already flagged: nothing more to do. The flag is now the last status
	//    change, so the count restarts from it.
	check("already flagged", "aftest-key", false, 0, "flagged")

	// 4. An admin sets it back to active: the count starts again from there.
	if _, err := d.SetCredentialStatus("aftest-key", "active", "reviewed", "admin@test"); err != nil {
		t.Fatal(err)
	}
	check("reset by admin", "aftest-key", false, 0, "active")
	evidence("aftest-r5", "server_in", "aftest-key", "rejected")
	evidence("aftest-r6", "server_in", "aftest-key", "rejected")
	check("rejections after reset, at the limit", "aftest-key", false, 2, "active")
	evidence("aftest-r7", "server_in", "aftest-key", "rejected")
	check("rejections after reset, over the limit", "aftest-key", true, 3, "flagged")

	// 5. A compromised key is never downgraded to flagged.
	if _, err := d.SetCredentialStatus("aftest-bad", "compromised", "leaked", "admin@test"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"aftest-b1", "aftest-b2", "aftest-b3", "aftest-b4"} {
		evidence(r, "server_in", "aftest-bad", "rejected")
	}
	check("compromised key", "aftest-bad", false, 4, "compromised")

	// 6. A limit of 0 is off.
	if flagged, _, _ := d.FlagCredentialOnRejections("aftest-key", 0); flagged {
		t.Error("limit 0: flagged, want off")
	}
}
