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
	// The observer's own clock. Without this the row gets the time it was
	// stored, which is a different thing whenever anything is slow.
	if got.ObservedAt == nil {
		t.Fatal("observed_at should have been read")
	}
	if *got.ObservedAt != 1789119652.8996422 {
		t.Errorf("want 1789119652.8996422, got %v", *got.ObservedAt)
	}
}

// A record with no time is still storable. The database fills one in.
func TestAMissingTimeIsAllowed(t *testing.T) {
	var got authEvidenceInput
	body := `{"request_id":"s","source":"server_in"}`
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.ObservedAt != nil {
		t.Errorf("want nil, got %v", *got.ObservedAt)
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

func TestBuildIntentAuthEvidence_OrderAndFilter(t *testing.T) {
	ts := func(f float64) *float64 { return &f }
	interactions := []*db.InteractionRecord{
		{IntentID: "nft", InteractionID: "nft-10", Signature: "sigC"},
		{IntentID: "nft", InteractionID: "nft-2", Signature: "sigB"},
		{IntentID: "nft", InteractionID: "nft-1", Signature: "sigA"},
		{IntentID: "nft", InteractionID: "nft-3", Signature: ""},
	}
	byRequest := map[string][]*db.AuthEvidenceRecord{
		"sigA": {
			{RequestID: "sigA", Source: "server_out", Destination: "db", ObservedAt: ts(200)},
			{RequestID: "sigA", Source: "server_in", ObservedAt: ts(100)},
		},
		"sigC": {{RequestID: "sigC", Source: "server_in"}},
	}

	got := buildIntentAuthEvidence(interactions, byRequest)

	if len(got) != 2 {
		t.Fatalf("want 2 interactions with evidence, got %d", len(got))
	}
	if got[0].InteractionID != "nft-1" || got[1].InteractionID != "nft-10" {
		t.Errorf("want hop order nft-1, nft-10; got %s, %s", got[0].InteractionID, got[1].InteractionID)
	}
	if got[0].Position != 1 || got[1].Position != 10 {
		t.Errorf("want positions 1, 10; got %d, %d", got[0].Position, got[1].Position)
	}
	ev := got[0].Evidence
	if len(ev) != 2 || ev[0].Source != "server_in" || ev[1].Source != "server_out" {
		t.Errorf("want evidence ordered by observed time, got %+v", ev)
	}
	if ev[0].ObservedAt == nil || ev[0].ObservedAt.Unix() != 100 {
		t.Errorf("want observedAt 100, got %v", ev[0].ObservedAt)
	}
}
