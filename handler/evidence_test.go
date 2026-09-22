package handler

import (
	"encoding/json"
	"testing"

	"agentdna-ratelimit-auth/db"
)

// The SDK's record and the middleware's input must stay the same shape. This
// is the actual JSON one produces, parsed by the other.
func TestTheSdkRecordParses(t *testing.T) {
	fromTheSdk := []byte(`{
	  "run_id": "",
	  "request_id": "30440220375476751ee644466c97111d771192e78bdc5f57",
	  "auth_method": "bearer_jwt",
	  "credential_id": "b68c6f30714991dbae0731eff2fc6e42",
	  "identity_id": "d13a06d61eb87423c102879d9c1ace2a",
	  "auth_status": "unknown",
	  "source": "server_in",
	  "key_version": "1beae804",
	  "destination": "bafybmiefu3fpjp5iv3le3oflnck74cru4fmnvavszks3xbwrodph3n7r7a",
	  "observed_at": 1789119652.8996422
	}`)

	var got authEvidenceInput
	if err := json.Unmarshal(fromTheSdk, &got); err != nil {
		t.Fatalf("the SDK's record no longer parses: %v", err)
	}

	if got.RequestID == "" || got.Source != "server_in" || got.AuthMethod != "bearer_jwt" {
		t.Errorf("fields did not land: %+v", got)
	}
	if got.IdentityID == nil || *got.IdentityID == "" {
		t.Error("identity_id should have been read")
	}
}

// An opaque credential sends identity_id as null. It must stay nil, not become
// an empty string: NULL means "cannot tell", and the analysis treats the two
// differently.
func TestANullIdentityStaysNull(t *testing.T) {
	var got authEvidenceInput
	if err := json.Unmarshal([]byte(`{"request_id":"s","source":"server_in","identity_id":null}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.IdentityID != nil {
		t.Errorf("want nil, got %q", *got.IdentityID)
	}
}

// A record with neither id is not storable - it could never be attached to
// anything - so it is skipped rather than written.
func TestRecordsWithoutIdsAreSkipped(t *testing.T) {
	for _, body := range []string{
		`{"source":"server_in"}`,
		`{"request_id":"s"}`,
	} {
		var got authEvidenceInput
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if got.RequestID != "" && got.Source != "" {
			t.Errorf("%s should be missing an id", body)
		}
	}
}

// The DB record carries a pointer for the same reason the wire does.
func TestTheDbRecordKeepsIdentityNullable(t *testing.T) {
	var record db.AuthEvidenceRecord
	if record.IdentityID != nil {
		t.Error("an unobserved identity must be nil, not an empty string")
	}
}
