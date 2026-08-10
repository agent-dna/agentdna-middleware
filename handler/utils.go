package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

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
// to the original initiator. Handles parallel branches via the full parent_envelope array.
func extractInteractionsFromEnvelopes(root *workflowEnvelope) []interactionExtract {
	if root == nil {
		return nil
	}

	all := collectAllEnvelopes(root)
	if len(all) == 0 {
		return nil
	}
	// Build parent→child edges by walking from the root (newest) down each branch.
	type edge struct {
		parent *workflowEnvelope
		child  *workflowEnvelope
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
			edges = append(edges, edge{parent: p, child: e})
			buildEdges(p)
		}
	}
	buildEdges(root)

	// Sort edges chronologically by child epoch (the child is the "newer" side).
	sort.Slice(edges, func(i, j int) bool { return edges[i].child.Epoch < edges[j].child.Epoch })

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
			Message:   ed.parent.Payload,
			Signature: ed.parent.Signature,
			Epoch:     ed.parent.Epoch,
		})
		seenAsFrom[fromDID] = true
	}

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

func parseChainNFT(data string) (*chainNFTData, error) {
	var d chainNFTData
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return nil, fmt.Errorf("parseChainNFT: %v", err)
	}
	return &d, nil
}

// walkChain collects all blocks from outermost→innermost then reverses
// so the result is chronological: innermost (intent/trigger) → outermost (verify).
func walkChain(root *chainBlock) []*chainBlock {
	var blocks []*chainBlock
	for b := root; b != nil; b = b.Envelope.ParentBlock {
		blocks = append(blocks, b)
	}
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}
	return blocks
}

// detectFlowType classifies the chain into one of the 8 flow types.
func detectFlowType(blocks []*chainBlock) string {
	hasTrigger, hasApproval, hasCBAC, hasSubResp, hasAttempts := false, false, false, false, false
	agentOutbound := 0
	for _, b := range blocks {
		switch b.Type {
		case "trigger":
			hasTrigger = true
		case "approval":
			hasApproval = true
		case "delegate":
			agentOutbound++
			if b.Envelope.Payload["attempts"] != nil {
				hasAttempts = true
			}
		case "execute":
			agentOutbound++
			if b.Envelope.Payload["attempts"] != nil {
				hasAttempts = true
			}
		case "response":
			if _, ok := b.Envelope.Payload["cbac"]; ok {
				hasCBAC = true
			}
			if _, ok := b.Envelope.Payload["sub_responses"]; ok {
				hasSubResp = true
			}
		}
	}
	switch {
	case hasTrigger:
		return "external_trigger"
	case hasApproval:
		return "cosign"
	case hasAttempts:
		return "retry"
	case hasSubResp:
		return "fan_out"
	case hasCBAC && agentOutbound > 2:
		return "delegated_cbac"
	case hasCBAC:
		return "cbac"
	case agentOutbound > 2:
		return "delegated"
	default:
		return "simple"
	}
}

// extractInteractions returns one interactionExtract per hop in the chain.
// Every consecutive block pair is recorded. When the direction transitions from
// inbound to outbound on the same agent, any cbac tool_call for that agent is
// inserted at that position rather than at the end.
func extractInteractions(blocks []*chainBlock) []interactionExtract {
	// Pre-collect cbac app entries keyed by agent DID.
	cbacApps := map[string]interactionExtract{}
	for _, b := range blocks {
		if b.Type != "response" {
			continue
		}
		cbacRaw, ok := b.Envelope.Payload["cbac"]
		if !ok || cbacRaw == nil {
			continue
		}
		cbacMap, ok := cbacRaw.(map[string]any)
		if !ok {
			continue
		}
		app, _ := cbacMap["app"].(string)
		if app == "" {
			continue
		}
		decision, _ := cbacMap["decision"].(string)
		threat := decision == "deny" || !b.Verification.SignatureValid || len(b.Verification.TrustIssues) > 0
		cbacApps[b.Agent] = interactionExtract{
			FromDID:   b.Agent,
			FromName:  b.Name,
			ToDID:     app,
			ToName:    app,
			Type:      "tool_call",
			Direction: "outbound",
			Threat:    threat,
		}
	}

	var result []interactionExtract

	for i := 0; i < len(blocks)-1; i++ {
		from := blocks[i]
		to := blocks[i+1]

		// Same agent in consecutive blocks — insert agent→app and app→agent, skip the self-hop.
		if from.Agent == to.Agent {
			if toolCall, ok := cbacApps[from.Agent]; ok {
				// Agent → Application
				result = append(result, toolCall)
				// Application → Agent
				result = append(result, interactionExtract{
					FromDID:   toolCall.ToDID,
					FromName:  toolCall.ToName,
					ToDID:     from.Agent,
					ToName:    from.Name,
					Type:      "tool_response",
					Direction: "inbound",
					Threat:    toolCall.Threat,
				})
				delete(cbacApps, from.Agent)
			}
			continue
		}

		threat := !from.Verification.SignatureValid || len(from.Verification.TrustIssues) > 0
		result = append(result, interactionExtract{
			FromDID:   from.Agent,
			FromName:  from.Name,
			ToDID:     to.Agent,
			ToName:    to.Name,
			Type:      from.Type,
			Direction: from.Direction,
			Threat:    threat,
		})
	}

	return result
}

// resolveActorName looks up a display name for the given DID from the agents
// table first, then the users table. Falls back to the envelope-provided name
// if neither has a record or the DID is empty.
func (h *Handler) resolveActorName(did, fallback string) string {
	if did == "" || did == "none" {
		return fallback
	}
	if agent, err := h.db.GetAgentInfo(did); err == nil && agent.AgentName != "" {
		return agent.AgentName
	}
	if name, err := h.db.GetOrgUserNameByDID(did); err == nil && name != "" {
		return name
	}
	return fallback
}
