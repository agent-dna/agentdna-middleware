package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

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
