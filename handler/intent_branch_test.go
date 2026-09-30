package handler

import (
	"testing"

	"agentdna-ratelimit-auth/db"
)

func hop(id, hash, from, to string) db.IntentHopRow {
	return db.IntentHopRow{InteractionID: id, Hash: hash, From: from, To: to}
}

func extract(hash, from, to string) interactionExtract {
	return interactionExtract{Hash: hash, FromDID: from, ToDID: to}
}

func TestResolveBranchIDs_NewIntent(t *testing.T) {
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "app"),
	}
	got := resolveBranchIDs("nft1", nil, interactions)
	want := []string{"nft1-1", "nft1-2"}
	if len(got.InsertIDs) != len(want) {
		t.Fatalf("InsertIDs = %v, want %v", got.InsertIDs, want)
	}
	for i, id := range want {
		if got.InsertIDs[i] != id {
			t.Errorf("InsertIDs[%d] = %s, want %s", i, got.InsertIDs[i], id)
		}
	}
	if got.FirstNew != 0 {
		t.Errorf("FirstNew = %d, want 0", got.FirstNew)
	}
	if len(got.Renamed) != 0 {
		t.Errorf("Renamed = %v, want none", got.Renamed)
	}
}

func TestResolveBranchIDs_FullyDuplicate(t *testing.T) {
	existing := []db.IntentHopRow{
		hop("nft1-1", "h1", "u", "a"),
		hop("nft1-2", "h2", "a", "app"),
	}
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "app"),
	}
	got := resolveBranchIDs("nft1", existing, interactions)
	if len(got.InsertIDs) != 0 || len(got.Renamed) != 0 {
		t.Fatalf("expected empty assignment for fully duplicate replay, got %+v", got)
	}
}

func TestResolveBranchIDs_PureExtension(t *testing.T) {
	existing := []db.IntentHopRow{
		hop("nft1-1", "h1", "u", "a"),
	}
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "app"),
	}
	got := resolveBranchIDs("nft1", existing, interactions)
	if len(got.Renamed) != 0 {
		t.Fatalf("pure extension should not rename anything, got %v", got.Renamed)
	}
	want := []string{"nft1-2"}
	if len(got.InsertIDs) != 1 || got.InsertIDs[0] != want[0] {
		t.Fatalf("InsertIDs = %v, want %v", got.InsertIDs, want)
	}
	if got.FirstNew != 1 {
		t.Errorf("FirstNew = %d, want 1", got.FirstNew)
	}
}

// TestResolveBranchIDs_FirstFork mirrors the user's own example: two hops
// shared (positions 1,2), then txn1's hop 3 and txn2's hop 3 differ. txn1 is
// already stored as plain trunk (nft1-1, nft1-2, nft1-3). txn2 arrives with
// the same first two hops but a different third hop, so this discovers a
// fork at position 3: nft1-3 must be relabeled to nft1-3-a-1, and txn2's
// diverging hop becomes nft1-3-b-1.
func TestResolveBranchIDs_FirstFork(t *testing.T) {
	existing := []db.IntentHopRow{
		hop("nft1-1", "h1", "u", "a"),
		hop("nft1-2", "h2", "a", "b"),
		hop("nft1-3", "h3-issues", "b", "github"),
	}
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "b"),
		extract("h3-prs", "b", "github"), // diverges here
	}
	got := resolveBranchIDs("nft1", existing, interactions)

	if len(got.Renamed) != 1 || got.Renamed[0].From != "nft1-3" || got.Renamed[0].To != "nft1-3-a-1" {
		t.Fatalf("Renamed = %v, want [{nft1-3 nft1-3-a-1}]", got.Renamed)
	}
	if len(got.InsertIDs) != 1 || got.InsertIDs[0] != "nft1-3-b-1" {
		t.Fatalf("InsertIDs = %v, want [nft1-3-b-1]", got.InsertIDs)
	}
	if got.FirstNew != 2 {
		t.Errorf("FirstNew = %d, want 2", got.FirstNew)
	}
}

// TestResolveBranchIDs_ThirdTxnNewBranch checks a third txn arriving after
// the fork above already exists (branches "a" and "b" both stored at
// position 3): a third, distinct hop at that position gets the next letter
// ("c"), with no further renaming since the fork was already discovered.
func TestResolveBranchIDs_ThirdTxnNewBranch(t *testing.T) {
	existing := []db.IntentHopRow{
		hop("nft1-1", "h1", "u", "a"),
		hop("nft1-2", "h2", "a", "b"),
		hop("nft1-3-a-1", "h3-issues", "b", "github"),
		hop("nft1-3-b-1", "h3-prs", "b", "github"),
	}
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "b"),
		extract("h3-commits", "b", "github"), // a third, distinct option
	}
	got := resolveBranchIDs("nft1", existing, interactions)

	if len(got.Renamed) != 0 {
		t.Fatalf("no renaming expected once the fork is already known, got %v", got.Renamed)
	}
	if len(got.InsertIDs) != 1 || got.InsertIDs[0] != "nft1-3-c-1" {
		t.Fatalf("InsertIDs = %v, want [nft1-3-c-1]", got.InsertIDs)
	}
}

// TestResolveBranchIDs_ExtendExistingBranch checks a txn that repeats branch
// "b"'s existing hop and then adds a new one after it — a pure extension of
// branch "b", not a new branch.
func TestResolveBranchIDs_ExtendExistingBranch(t *testing.T) {
	existing := []db.IntentHopRow{
		hop("nft1-1", "h1", "u", "a"),
		hop("nft1-2", "h2", "a", "b"),
		hop("nft1-3-a-1", "h3-issues", "b", "github"),
		hop("nft1-3-b-1", "h3-prs", "b", "github"),
	}
	interactions := []interactionExtract{
		extract("h1", "u", "a"),
		extract("h2", "a", "b"),
		extract("h3-prs", "b", "github"),
		extract("h4-merge", "b", "github"),
	}
	got := resolveBranchIDs("nft1", existing, interactions)

	if len(got.Renamed) != 0 {
		t.Fatalf("extending an existing branch should not rename anything, got %v", got.Renamed)
	}
	if len(got.InsertIDs) != 1 || got.InsertIDs[0] != "nft1-3-b-2" {
		t.Fatalf("InsertIDs = %v, want [nft1-3-b-2]", got.InsertIDs)
	}
	if got.FirstNew != 3 {
		t.Errorf("FirstNew = %d, want 3", got.FirstNew)
	}
}

func TestParseHopID(t *testing.T) {
	cases := []struct {
		id       string
		wantOK   bool
		wantKind hopIDKind
	}{
		{"nft1-1", true, hopKindTrunk},
		{"nft1-3-a-1", true, hopKindBranch},
		{"nft1-block-5", false, 0},
		{"other-1", false, 0},
		{"nft1-threat-h3", false, 0},
	}
	for _, c := range cases {
		p, ok := parseHopID("nft1", c.id)
		if ok != c.wantOK {
			t.Errorf("parseHopID(%q) ok = %v, want %v", c.id, ok, c.wantOK)
			continue
		}
		if ok && p.kind != c.wantKind {
			t.Errorf("parseHopID(%q) kind = %v, want %v", c.id, p.kind, c.wantKind)
		}
	}
}
