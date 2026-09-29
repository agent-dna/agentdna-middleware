package handler

import (
	"testing"

	"agentdna-ratelimit-auth/db"
)

func id(s string) *string { return &s }

func hop(interactionID, signature string) hopRef {
	return hopRef{InteractionID: interactionID, Signature: signature}
}

func observed(method, credential string, identity *string) HopEvidence {
	return HopEvidence{
		Status:       EvidenceObserved,
		Sources:      []string{"server_in"},
		AuthMethod:   method,
		CredentialID: credential,
		IdentityID:   identity,
		AuthStatus:   "unknown",
	}
}

// A refreshed token is a new credential for the same identity. Reporting it as
// a handoff is the false positive the two fingerprints exist to avoid.
func TestARefreshIsNotAnIdentityChange(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2")}
	evidence := map[string]HopEvidence{
		"i-1": observed("bearer_jwt", "cred-A", id("priya")),
		"i-2": observed("bearer_jwt", "cred-B", id("priya")),
	}

	got := analyseContinuity(order, evidence)

	if got.CredentialChangedAt != "i-2" {
		t.Errorf("credential change: want i-2, got %q", got.CredentialChangedAt)
	}
	if got.IdentityChangedAt != "" {
		t.Errorf("identity must not change on a refresh, got %q", got.IdentityChangedAt)
	}
	if !got.IdentityContinued {
		t.Error("identity should have continued")
	}
}

// An opaque credential means we stopped being able to tell whose it is. It does
// not mean the identity changed, and must never be reported as one.
func TestANullIdentityIsUnknownNotChanged(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2"), hop("i-3", "sig-3")}
	evidence := map[string]HopEvidence{
		"i-1": observed("bearer_jwt", "cred-A", id("priya")),
		"i-2": observed("bearer_jwt", "cred-A", id("priya")),
		"i-3": observed("api_key", "cred-C", nil),
	}

	got := analyseContinuity(order, evidence)

	if got.IdentityUnknownFrom != "i-3" {
		t.Errorf("unknown from: want i-3, got %q", got.IdentityUnknownFrom)
	}
	if got.IdentityChangedAt != "" {
		t.Errorf("a null identity is not a change, got %q", got.IdentityChangedAt)
	}
	if got.CredentialChangedAt != "i-3" {
		t.Errorf("credential change: want i-3, got %q", got.CredentialChangedAt)
	}
}

// A different identity, observed on both sides, is a real change.
func TestADifferentIdentityIsAChange(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2")}
	evidence := map[string]HopEvidence{
		"i-1": observed("bearer_jwt", "cred-A", id("priya")),
		"i-2": observed("bearer_jwt", "cred-B", id("hari")),
	}

	got := analyseContinuity(order, evidence)

	if got.IdentityChangedAt != "i-2" {
		t.Errorf("identity change: want i-2, got %q", got.IdentityChangedAt)
	}
	if got.IdentityContinued {
		t.Error("identity should not have continued")
	}
}

// A missing record reduces coverage. It must move no conclusion, because
// whatever happened there was not observed.
func TestMissingEvidenceReducesCoverageOnly(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2"), hop("i-3", "sig-3")}
	evidence := map[string]HopEvidence{
		"i-1": observed("bearer_jwt", "cred-A", id("priya")),
		"i-2": {Status: EvidenceNotObserved},
		"i-3": observed("bearer_jwt", "cred-A", id("priya")),
	}

	got := analyseContinuity(order, evidence)

	if got.RequestsTotal != 3 || got.RequestsObserved != 2 {
		t.Errorf("coverage: want 2 of 3, got %d of %d", got.RequestsObserved, got.RequestsTotal)
	}
	if got.CredentialChangedAt != "" || got.IdentityChangedAt != "" {
		t.Error("an unobserved hop must not produce a conclusion")
	}
}

// One request that fans out to concurrent children produces several
// interactions sharing a signature. Counting rows would report more requests
// than were made.
func TestFanOutCountsRequestsNotRows(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-1"), hop("i-3", "sig-2")}
	evidence := map[string]HopEvidence{
		"i-1": observed("bearer_jwt", "cred-A", id("priya")),
		"i-2": observed("bearer_jwt", "cred-A", id("priya")),
		"i-3": observed("bearer_jwt", "cred-A", id("priya")),
	}

	got := analyseContinuity(order, evidence)

	if got.RequestsTotal != 2 {
		t.Errorf("want 2 requests, got %d", got.RequestsTotal)
	}
}

// Hops carrying no credential - anything that never left the process - have no
// answer, and must not start the run or count as observed.
func TestHopsWithoutCredentialsAreSkipped(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2")}
	evidence := map[string]HopEvidence{
		"i-1": observed("none", "", nil),
		"i-2": observed("bearer_jwt", "cred-A", id("priya")),
	}

	got := analyseContinuity(order, evidence)

	if got.StartingCredential != "cred-A" {
		t.Errorf("the run starts at the first credential-bearing hop, got %q", got.StartingCredential)
	}
	if got.RequestsObserved != 1 {
		t.Errorf("want 1 observed, got %d", got.RequestsObserved)
	}
}

// Interactions are named "<intentID>-<n>". Sorting them as text gives
// 1, 10, 11, 2 - which walks the run in the wrong order.
func TestOrderingUsesTheNumericSuffix(t *testing.T) {
	interactions := []*db.InteractionRecord{
		{InteractionID: "intent-abc-10", Signature: "sig-10"},
		{InteractionID: "intent-abc-2", Signature: "sig-2"},
		{InteractionID: "intent-abc-1", Signature: "sig-1"},
	}

	got := interactionOrder(interactions)

	want := []string{"intent-abc-1", "intent-abc-2", "intent-abc-10"}
	for i, expected := range want {
		if got[i].InteractionID != expected {
			t.Errorf("position %d: want %s, got %s", i, expected, got[i].InteractionID)
		}
	}
	if suffixIndex("no-suffix-here") != 0 {
		t.Error("an unparseable suffix falls back to 0 rather than panicking")
	}
}

// A single observation point is "observed", not "confirmed" - there is nothing
// to have confirmed it against.
func TestOneSourceIsObservedNotConfirmed(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-A", KeyVersion: "v1"},
	})

	if got.Status != EvidenceObserved {
		t.Errorf("want %q, got %q", EvidenceObserved, got.Status)
	}
}

// Two points that saw the same credential confirm each other.
func TestAgreeingSourcesConfirm(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-A", KeyVersion: "v1"},
		{Source: "gateway", CredentialID: "cred-A", KeyVersion: "v1"},
	})

	if got.Status != EvidenceConfirmed {
		t.Errorf("want %q, got %q", EvidenceConfirmed, got.Status)
	}
}

// Two points that saw different credentials means something between them
// changed it. We report the disagreement; we do not pick a winner.
func TestDisagreeingSourcesMismatch(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-A", KeyVersion: "v1"},
		{Source: "gateway", CredentialID: "cred-B", KeyVersion: "v1"},
	})

	if got.Status != EvidenceMismatch {
		t.Errorf("want %q, got %q", EvidenceMismatch, got.Status)
	}
}

// Fingerprints made with different keys are not comparable. A key change must
// not render as a disagreement that never happened.
func TestDifferentKeyVersionsAreNotCompared(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-A", KeyVersion: "v1"},
		{Source: "gateway", CredentialID: "cred-B", KeyVersion: "v2"},
	})

	if got.Status == EvidenceMismatch {
		t.Error("records from different keys must not be reported as disagreeing")
	}
}

// A run nobody watched reports nothing, rather than an empty-looking clean run.
func TestAnUnobservedRunConcludesNothing(t *testing.T) {
	order := []hopRef{hop("i-1", "sig-1"), hop("i-2", "sig-2")}
	evidence := map[string]HopEvidence{
		"i-1": {Status: EvidenceNotObserved},
		"i-2": {Status: EvidenceNotObserved},
	}

	got := analyseContinuity(order, evidence)

	if got.RequestsObserved != 0 || got.RequestsTotal != 2 {
		t.Errorf("coverage: want 0 of 2, got %d of %d", got.RequestsObserved, got.RequestsTotal)
	}
	if got.StartingCredential != "" || got.IdentityContinued {
		t.Error("nothing was observed, so nothing should be concluded")
	}
}

// The outbound leg is a different hop, and its credential is meant to differ.
// Comparing it with what arrived reported a mismatch on every hop that did its
// job - a server answering a request with its own backend credential.
func TestTheOutboundLegIsNotComparedWithWhatArrived(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-user", KeyVersion: "v1"},
		{Source: "server_out", CredentialID: "cred-service-account", KeyVersion: "v1"},
	})

	if got.Status == EvidenceMismatch {
		t.Error("the next leg's credential must not read as a disagreement")
	}
	if got.Status != EvidenceObserved {
		t.Errorf("want %q, got %q", EvidenceObserved, got.Status)
	}
}

// The payoff of watching both ends: the agent sent it, the server received it,
// and they agree. The server's own onward call sits alongside, uncompared.
func TestBothEndsConfirmEvenBesideTheOutboundLeg(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "client_out", CredentialID: "cred-user", KeyVersion: "v1"},
		{Source: "server_in", CredentialID: "cred-user", KeyVersion: "v1"},
		{Source: "server_out", CredentialID: "cred-service-account", KeyVersion: "v1"},
	})

	if got.Status != EvidenceConfirmed {
		t.Errorf("want %q, got %q", EvidenceConfirmed, got.Status)
	}
	if len(got.Sources) != 3 {
		t.Errorf("all three points should still be reported, got %v", got.Sources)
	}
}

// A header stripped between the agent and the server. This is the case the
// second observation point exists to catch.
func TestBothEndsDisagreeWhenTheCredentialChangedInFlight(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "client_out", CredentialID: "cred-sent", KeyVersion: "v1"},
		{Source: "server_in", CredentialID: "cred-arrived", KeyVersion: "v1"},
	})

	if got.Status != EvidenceMismatch {
		t.Errorf("want %q, got %q", EvidenceMismatch, got.Status)
	}
}

// The query does not order its rows, so the hop must not be described by
// whichever record happened to come back first.
func TestTheHopIsDescribedByAWireRecordWhateverTheOrder(t *testing.T) {
	forwards := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_in", CredentialID: "cred-user", AuthMethod: "bearer_jwt"},
		{Source: "server_out", CredentialID: "cred-service-account", AuthMethod: "api_key"},
	})
	backwards := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_out", CredentialID: "cred-service-account", AuthMethod: "api_key"},
		{Source: "server_in", CredentialID: "cred-user", AuthMethod: "bearer_jwt"},
	})

	for _, got := range []HopEvidence{forwards, backwards} {
		if got.CredentialID != "cred-user" || got.AuthMethod != "bearer_jwt" {
			t.Errorf("the hop should be described by what arrived, got %+v", got)
		}
	}
}

// Only the outbound leg was observed. That key is the server's, not the
// caller's, so it is listed as a backend call and the hop's own credential
// stays empty - it must not start or change the run's identity.
func TestTheOutboundLegAloneIsABackendCallNotTheHopsCredential(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_out", CredentialID: "cred-service-account", AuthMethod: "api_key", Destination: "api.github.com"},
	})

	if got.Status != EvidenceObserved || got.CredentialID != "" || got.AuthMethod != "" {
		t.Errorf("want observed with no credential of its own, got %+v", got)
	}
	if len(got.BackendCalls) != 1 || got.BackendCalls[0].CredentialID != "cred-service-account" {
		t.Errorf("want the outbound credential as a backend call, got %+v", got.BackendCalls)
	}

	continuity := analyseContinuity([]hopRef{hop("i-1", "sig-1")}, map[string]HopEvidence{"i-1": got})
	if continuity.StartingCredential != "" || continuity.RequestsObserved != 0 {
		t.Errorf("a backend key must not start the run, got %+v", continuity)
	}
}

// The first real run: one tool call, and the server made two backend calls -
// one to GitHub with its own token. Both are shown, in a stable order.
func TestEveryBackendCallOfAHopIsShown(t *testing.T) {
	got := evidenceForHop([]*db.AuthEvidenceRecord{
		{Source: "server_out", Destination: "api.github.com", AuthMethod: "bearer_opaque", CredentialID: "cred-github", AuthStatus: "accepted"},
		{Source: "client_out", Destination: "127.0.0.1", AuthMethod: "none"},
		{Source: "server_out", Destination: "analytics.internal", AuthMethod: "api_key", CredentialID: "cred-analytics", AuthStatus: "rejected"},
		{Source: "server_in", Destination: "did:mcp-server", AuthMethod: "none"},
	})

	if len(got.BackendCalls) != 2 {
		t.Fatalf("want 2 backend calls, got %+v", got.BackendCalls)
	}
	if got.BackendCalls[0].Destination != "analytics.internal" || got.BackendCalls[1].Destination != "api.github.com" {
		t.Errorf("want calls sorted by destination, got %+v", got.BackendCalls)
	}
	if got.BackendCalls[1].CredentialID != "cred-github" || got.BackendCalls[1].AuthStatus != "accepted" {
		t.Errorf("the GitHub call lost its details: %+v", got.BackendCalls[1])
	}
	if want := []string{"client_out", "server_in", "server_out"}; len(got.Sources) != 3 ||
		got.Sources[0] != want[0] || got.Sources[1] != want[1] || got.Sources[2] != want[2] {
		t.Errorf("each source listed once, got %v", got.Sources)
	}
}
