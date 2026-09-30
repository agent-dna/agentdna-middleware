package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"agentdna-ratelimit-auth/db"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// GetID generates a deterministic CIDv0 from a name string.
func GetID(name string) (string, error) {
	digest := sha256.Sum256([]byte(name))
	multihash, err := mh.Encode(digest[:], mh.SHA2_256)
	if err != nil {
		return "", err
	}
	return cid.NewCidV0(multihash).String(), nil
}

func parseNFTType(data string) (string, error) {
	var base struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(data), &base); err != nil {
		return "", fmt.Errorf("parseNFTType: %v", err)
	}
	return base.Type, nil
}

func parseUserNFT(data string) (*userNFTData, error) {
	var d userNFTData
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return nil, fmt.Errorf("parseUserNFT: %v", err)
	}
	return &d, nil
}

func parseAgentNFT(data string) (*agentNFTData, error) {
	var d agentNFTData
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return nil, fmt.Errorf("parseAgentNFT: %v", err)
	}
	return &d, nil
}

func parseIntentWorkflow(data string) (*intentWorkflowData, error) {
	var d intentWorkflowData
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return nil, fmt.Errorf("parseIntentWorkflow: %v", err)
	}
	return &d, nil
}

// extractPayloadText returns the human-readable text from an envelope payload.
// Payload can be a plain JSON string or a JSON array of content blocks
// (e.g. [{type:"text", text:"..."}]). Returns the raw JSON bytes as a string
// if neither form matches.
func extractPayloadText(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	// Try array of content blocks.
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(payload, &blocks) == nil {
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				return b.Text
			}
		}
	}
	// Try plain string.
	var s string
	if json.Unmarshal(payload, &s) == nil {
		return s
	}
	return string(payload)
}

// walkEnvelopes unrolls the parent_envelope chain into chronological order (oldest first).
// Follows only the first parent at each step — used for display/raw endpoints.
// For interaction extraction use extractInteractionsFromEnvelopes which handles parallel branches.
func walkEnvelopes(root *workflowEnvelope) []*workflowEnvelope {
	var envs []*workflowEnvelope
	for e := root; e != nil; {
		envs = append(envs, e)
		if len(e.ParentEnvelope) > 0 {
			e = e.ParentEnvelope[0]
		} else {
			e = nil
		}
	}
	for i, j := 0, len(envs)-1; i < j; i, j = i+1, j-1 {
		envs[i], envs[j] = envs[j], envs[i]
	}
	return envs
}

// collectAllEnvelopes does a full DFS over the envelope DAG, visiting every branch.
// Returns all unique envelopes sorted by epoch ascending (oldest first).
func collectAllEnvelopes(root *workflowEnvelope) []*workflowEnvelope {
	seen := map[*workflowEnvelope]bool{}
	var all []*workflowEnvelope
	var dfs func(e *workflowEnvelope)
	dfs = func(e *workflowEnvelope) {
		if e == nil || seen[e] {
			return
		}
		seen[e] = true
		all = append(all, e)
		for _, p := range e.ParentEnvelope {
			dfs(p)
		}
	}
	dfs(root)
	sort.Slice(all, func(i, j int) bool { return all[i].Epoch < all[j].Epoch })
	return all
}

// extractInteractionsFromEnvelopes traverses the full envelope DAG and returns one
// interaction per parent→child edge, plus a final edge from the newest envelope back
// to the executor (the entity that submitted the tx). Handles parallel branches via
// the full parent_envelope array.
func extractInteractionsFromEnvelopes(root *workflowEnvelope, initiatorDID, executorDID string) []interactionExtract {
	if root == nil {
		return nil
	}

	all := collectAllEnvelopes(root)
	if len(all) == 0 {
		return nil
	}

	// Fall back to base envelope's From if no explicit initiator was provided.
	if initiatorDID == "" {
		initiatorDID = all[0].From
	}
	// Fall back to initiator if no explicit executor was provided.
	if executorDID == "" {
		executorDID = initiatorDID
	}

	// Build parent→child edges by walking from the root (newest) down each branch.
	// origIdx records construction order: buildEdges walks root→base (newest→oldest),
	// so a higher origIdx was appended later and is therefore structurally older.
	type edge struct {
		parent  *workflowEnvelope
		child   *workflowEnvelope
		origIdx int
	}
	var edges []edge
	visited := map[*workflowEnvelope]bool{}
	var buildEdges func(e *workflowEnvelope)
	buildEdges = func(e *workflowEnvelope) {
		if e == nil || visited[e] {
			return
		}
		visited[e] = true
		for _, p := range e.ParentEnvelope {
			edges = append(edges, edge{parent: p, child: e, origIdx: len(edges)})
			buildEdges(p)
		}
	}
	buildEdges(root)

	// Sort edges chronologically by child epoch (the child is the "newer" side).
	// Envelope epochs are only second-resolution, so a fast hop (e.g. an agent
	// immediately forwarding to its child) can tie on epoch with its neighbor —
	// break ties using the DAG structure itself (origIdx) rather than leaving it
	// to sort.Slice's unstable ordering, which produced nondeterministic results.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].child.Epoch != edges[j].child.Epoch {
			return edges[i].child.Epoch < edges[j].child.Epoch
		}
		return edges[i].origIdx > edges[j].origIdx
	})

	seenAsFrom := map[string]bool{}
	var result []interactionExtract

	for i, ed := range edges {
		fromDID := ed.parent.From
		toDID := ed.child.From
		threat := ed.parent.Code != 0 && ed.parent.Code != 1000
		result = append(result, interactionExtract{
			FromDID:   fromDID,
			ToDID:     toDID,
			Type:      deriveWorkflowInteractionType(fromDID, toDID, i, seenAsFrom),
			Threat:    threat,
			Message:   extractPayloadText(ed.parent.Payload),
			Signature: ed.parent.Signature,
			Hash:      ed.parent.Hash,
			Epoch:     ed.parent.Epoch,
		})
		seenAsFrom[fromDID] = true
	}

	// Closing edge: last envelope's sender → executor (response back to whoever
	// submitted the tx). Always added, even when root.From == executorDID — in
	// that case it's a self-loop (from == to == executorDID), so the provenance
	// line's final "to" is always the executor.
	threat := root.Code != 0 && root.Code != 1000
	result = append(result, interactionExtract{
		FromDID:   root.From,
		ToDID:     executorDID,
		Type:      deriveWorkflowInteractionType(root.From, executorDID, len(result), seenAsFrom),
		Threat:    threat,
		Message:   extractPayloadText(root.Payload),
		Signature: root.Signature,
		Hash:      root.Hash,
		Epoch:     root.Epoch,
	})

	return result
}

// deriveWorkflowInteractionType infers type from position and chain history.
// First hop is always a trigger; return hops (destination already sent) are responses;
// forward hops are delegates.
func deriveWorkflowInteractionType(fromDID, toDID string, idx int, seenAsFrom map[string]bool) string {
	if idx == 0 {
		return "trigger"
	}
	if seenAsFrom[toDID] || fromDID == toDID {
		return "response"
	}
	return "delegate"
}

func detectFlowTypeFromExtracts(interactions []interactionExtract) string {
	hasTrigger, hasToolCall, hasResponse := false, false, false
	delegateCount := 0
	for _, ix := range interactions {
		switch ix.Type {
		case "trigger":
			hasTrigger = true
		case "tool_call":
			hasToolCall = true
		case "delegate":
			delegateCount++
		case "response":
			hasResponse = true
		}
	}
	_ = hasResponse
	switch {
	case hasTrigger && hasToolCall && delegateCount > 1:
		return "delegated_cbac"
	case hasTrigger && hasToolCall:
		return "cbac"
	case hasTrigger && delegateCount > 1:
		return "delegated"
	case hasTrigger:
		return "external_trigger"
	case hasToolCall && delegateCount > 1:
		return "delegated_cbac"
	case hasToolCall:
		return "cbac"
	case delegateCount > 1:
		return "delegated"
	default:
		return "simple"
	}
}

// resolveActorName looks up a display name for the given DID from the agents
// table first, then the users table. Falls back to the envelope-provided name
// if neither has a record or the DID is empty.
// buildEnvelopeChain converts an ordered slice of IntentBlockRecords (oldest first)
// into a nested *workflowEnvelope tree for the /intent-block-data and /intent-diagram APIs.
func buildEnvelopeChain(blocks []*db.IntentBlockRecord) *workflowEnvelope {
	if len(blocks) == 0 {
		return nil
	}
	var prev *workflowEnvelope
	for _, b := range blocks {
		code := 1000
		if b.ThreatDetected {
			code = 2001
		}
		payloadJSON, _ := json.Marshal(b.Message)
		env := &workflowEnvelope{
			From:      b.FromDID,
			Payload:   json.RawMessage(payloadJSON),
			Epoch:     b.CreatedAt.Unix(),
			Code:      code,
			Signature: b.Signature,
			RawData:   b.RawData,
		}
		if prev != nil {
			env.ParentEnvelope = []*workflowEnvelope{prev}
		}
		prev = env
	}
	if prev != nil && len(blocks) > 0 {
		prev.To = blocks[len(blocks)-1].ToDID
	}
	return prev
}

// hopIDKind classifies an already-stored interaction_id by its shape, as
// produced by resolveBranchIDs: plain trunk ("<intentID>-N") or a branch hop
// ("<intentID>-<forkPos>-<letter>-<offset>").
type hopIDKind int

const (
	hopKindTrunk hopIDKind = iota
	hopKindBranch
)

type parsedHopID struct {
	kind   hopIDKind
	n      int // trunk position, or fork position for a branch hop
	letter string
	offset int
}

// parseHopID classifies an interaction_id belonging to intentID. IDs that
// don't match either shape (e.g. malformed rows from before this scheme, or
// simply garbage) are reported as !ok and ignored by the caller — safer than
// guessing, since a wrongly-classified row could corrupt the branch tree.
func parseHopID(intentID, id string) (parsedHopID, bool) {
	prefix := intentID + "-"
	if !strings.HasPrefix(id, prefix) {
		return parsedHopID{}, false
	}
	parts := strings.Split(id[len(prefix):], "-")
	switch len(parts) {
	case 1:
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			return parsedHopID{}, false
		}
		return parsedHopID{kind: hopKindTrunk, n: n}, true
	case 3:
		n, err1 := strconv.Atoi(parts[0])
		offset, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || parts[1] == "" {
			return parsedHopID{}, false
		}
		return parsedHopID{kind: hopKindBranch, n: n, letter: parts[1], offset: offset}, true
	default:
		return parsedHopID{}, false
	}
}

// branchAssignment is the result of matching a txn's hop sequence against
// whatever is already stored for its intent (nftId).
type branchAssignment struct {
	// InsertIDs are the interaction_ids to store for interactions[FirstNew:],
	// one per remaining hop in order. Empty when this txn is a fully
	// duplicate replay of hops already stored.
	InsertIDs []string
	FirstNew  int
	// Renamed lists existing trunk rows that need relabeling into a branch
	// because this txn revealed their position was actually a fork point.
	Renamed []db.RenamedInteractionID
}

// resolveBranchIDs compares a txn's hop sequence (already deduped within the
// call) against every hop already stored for intentID, and decides what (if
// anything) is new:
//   - fully duplicate replay: no existing branch was extended, nothing to insert.
//   - pure extension: the new hops just continue the trunk (or an existing
//     branch) further — no fork.
//   - a fork: the new hops diverge from an existing sequence at some position.
//     The first time a fork is discovered at a given position, the existing
//     trunk tail from that position onward is relabeled into branch "a" and
//     the new arrival becomes "b"; later forks at the same position get the
//     next unused letter. Only one level of branching is modeled — a further
//     divergence *within* an already-forked branch mints a new branch at the
//     original fork position rather than nesting, per the id scheme
//     "<intentID>-<forkPos>-<letter>-<offset>".
func resolveBranchIDs(intentID string, existing []db.IntentHopRow, interactions []interactionExtract) branchAssignment {
	type branchEntry struct {
		offset int
		row    db.IntentHopRow
	}

	trunk := map[int]db.IntentHopRow{}
	branches := map[int]map[string][]branchEntry{}
	maxTrunkN := 0
	for _, row := range existing {
		p, ok := parseHopID(intentID, row.InteractionID)
		if !ok {
			continue
		}
		if p.kind == hopKindTrunk {
			trunk[p.n] = row
			if p.n > maxTrunkN {
				maxTrunkN = p.n
			}
		} else {
			if branches[p.n] == nil {
				branches[p.n] = map[string][]branchEntry{}
			}
			branches[p.n][p.letter] = append(branches[p.n][p.letter], branchEntry{offset: p.offset, row: row})
		}
	}
	trunkSeq := make([]db.IntentHopRow, maxTrunkN)
	for n, row := range trunk {
		trunkSeq[n-1] = row
	}
	for forkPos := range branches {
		for letter := range branches[forkPos] {
			entries := branches[forkPos][letter]
			sort.Slice(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })
			branches[forkPos][letter] = entries
		}
	}

	same := func(a db.IntentHopRow, b interactionExtract) bool {
		return a.Hash == b.Hash && a.From == b.FromDID && a.To == b.ToDID
	}

	matched := 0
	for matched < len(trunkSeq) && matched < len(interactions) && same(trunkSeq[matched], interactions[matched]) {
		matched++
	}

	if matched == len(interactions) {
		return branchAssignment{} // fully duplicate replay
	}

	// forkPos (1-based) is where the new tail picks up: either a genuine
	// mismatch against trunk data still hanging off this intent, or simply
	// the next position after the trunk. trunkHasDataHere distinguishes the
	// two: it's true only when trunkSeq itself still has an (mismatching)
	// entry there. Once a fork is first discovered, every trunk row from that
	// position on is relabeled into a branch (below), so on any later call
	// trunkSeq must have already stopped short of forkPos — trunkHasDataHere
	// and an existing branches[forkPos] are mutually exclusive.
	forkPos := matched + 1
	trunkHasDataHere := matched < len(trunkSeq)

	if !trunkHasDataHere && len(branches[forkPos]) == 0 {
		// Pure extension — trunk has nothing more, and this position has
		// never forked before.
		ids := make([]string, 0, len(interactions)-matched)
		for i := matched; i < len(interactions); i++ {
			ids = append(ids, fmt.Sprintf("%s-%d", intentID, i+1))
		}
		return branchAssignment{InsertIDs: ids, FirstNew: matched}
	}

	// Does the new tail continue an already-known branch at this fork point?
	for letter, entries := range branches[forkPos] {
		if len(entries) == 0 || !same(entries[0].row, interactions[matched]) {
			continue
		}
		branchMatched := 0
		for branchMatched < len(entries) && matched+branchMatched < len(interactions) &&
			same(entries[branchMatched].row, interactions[matched+branchMatched]) {
			branchMatched++
		}
		if matched+branchMatched == len(interactions) {
			return branchAssignment{} // fully duplicate of this branch
		}
		if branchMatched == len(entries) {
			// Pure extension of this existing branch.
			ids := make([]string, 0, len(interactions)-matched-branchMatched)
			for i := matched + branchMatched; i < len(interactions); i++ {
				ids = append(ids, fmt.Sprintf("%s-%d-%s-%d", intentID, forkPos, letter, i-matched+1))
			}
			return branchAssignment{InsertIDs: ids, FirstNew: matched + branchMatched}
		}
		// Diverges further within this branch — minted as a brand new branch
		// at forkPos below rather than a nested sub-fork.
		break
	}

	// Brand new branch at forkPos.
	var renamed []db.RenamedInteractionID
	letter := string(rune('a' + len(branches[forkPos])))
	if len(branches[forkPos]) == 0 && trunkHasDataHere {
		// First fork ever discovered at forkPos — relabel the existing trunk
		// tail into branch "a" and use "b" for the new arrival.
		for n := forkPos; n <= maxTrunkN; n++ {
			oldID := fmt.Sprintf("%s-%d", intentID, n)
			newID := fmt.Sprintf("%s-%d-a-%d", intentID, forkPos, n-forkPos+1)
			renamed = append(renamed, db.RenamedInteractionID{From: oldID, To: newID})
		}
		letter = "b"
	}
	ids := make([]string, 0, len(interactions)-matched)
	for i := matched; i < len(interactions); i++ {
		ids = append(ids, fmt.Sprintf("%s-%d-%s-%d", intentID, forkPos, letter, i-matched+1))
	}
	return branchAssignment{InsertIDs: ids, FirstNew: matched, Renamed: renamed}
}

func (h *Handler) resolveActorName(did, fallback string) string {
	if did == "" || did == "none" {
		return fallback
	}
	if agent, err := h.db.GetAgentInfo(did); err == nil && agent.AgentName != "" {
		return agent.AgentName
	}
	if name, err := h.db.GetAgentNameByRequestDID(did); err == nil && name != "" {
		return name
	}
	if name, err := h.db.GetOrgUserNameByDID(did); err == nil && name != "" {
		return name
	}
	return fallback
}
