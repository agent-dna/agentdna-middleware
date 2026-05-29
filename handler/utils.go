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
// Every consecutive block pair is recorded regardless of direction.
// Response blocks with cbac → additional tool_call hops.
func extractInteractions(blocks []*chainBlock) []interactionExtract {
	var result []interactionExtract

	// One interaction per consecutive block pair (covers inbound + outbound).
	for i := 0; i < len(blocks)-1; i++ {
		from := blocks[i]
		to := blocks[i+1]
		threat := !from.Verification.SignatureValid || len(from.Verification.TrustIssues) > 0
		result = append(result, interactionExtract{
			FromDID:   from.Agent,
			FromName:  from.Name,
			ToDID:     to.Agent,
			ToName:    to.Name,
			BlockType: from.Type,
			Threat:    threat,
		})
	}

	// Tool calls: response blocks that carry a cbac decision.
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
		decision, _ := cbacMap["decision"].(string)
		if app == "" {
			continue
		}
		threat := decision == "deny" || !b.Verification.SignatureValid || len(b.Verification.TrustIssues) > 0
		result = append(result, interactionExtract{
			FromDID:   b.Agent,
			FromName:  b.Name,
			ToDID:     app,
			ToName:    app,
			BlockType: "tool_call",
			Threat:    threat,
		})
	}

	return result
}
