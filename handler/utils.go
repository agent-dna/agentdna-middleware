package handler

import (
	"encoding/json"
	"fmt"
)

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
