package handler

import (
	"testing"
)

// --- walkEnvelopes (linear display walk) ---

func TestWalkEnvelopes_SingleBlock(t *testing.T) {
	root := &workflowEnvelope{From: "user", Payload: "hello", Epoch: 1}
	envs := walkEnvelopes(root)
	if len(envs) != 1 {
		t.Fatalf("expected 1, got %d", len(envs))
	}
	if envs[0].From != "user" {
		t.Errorf("expected user, got %s", envs[0].From)
	}
}

func TestWalkEnvelopes_ChronologicalOrder(t *testing.T) {
	oldest := &workflowEnvelope{From: "user", Epoch: 1}
	middle := &workflowEnvelope{From: "agentA", Epoch: 2, ParentEnvelope: []*workflowEnvelope{oldest}}
	newest := &workflowEnvelope{From: "agentB", Epoch: 3, ParentEnvelope: []*workflowEnvelope{middle}}

	envs := walkEnvelopes(newest)
	if len(envs) != 3 {
		t.Fatalf("expected 3, got %d", len(envs))
	}
	if envs[0].From != "user" || envs[2].From != "agentB" {
		t.Errorf("wrong order: %s %s %s", envs[0].From, envs[1].From, envs[2].From)
	}
}

// --- collectAllEnvelopes (full DAG) ---

func TestCollectAllEnvelopes_Parallel(t *testing.T) {
	// DAG: user → agentA → agentB (parallel)
	//                    → agentC (parallel)
	//      agentB, agentC → agentA (merger)
	user := &workflowEnvelope{From: "user", Epoch: 1}
	agentA1 := &workflowEnvelope{From: "agentA", Epoch: 2, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Epoch: 3, ParentEnvelope: []*workflowEnvelope{agentA1}}
	agentC := &workflowEnvelope{From: "agentC", Epoch: 3, ParentEnvelope: []*workflowEnvelope{agentA1}}
	merger := &workflowEnvelope{From: "agentA", Epoch: 4, ParentEnvelope: []*workflowEnvelope{agentB, agentC}}

	all := collectAllEnvelopes(merger)
	if len(all) != 5 {
		t.Fatalf("expected 5 unique envelopes, got %d", len(all))
	}
	if all[0].From != "user" {
		t.Errorf("oldest should be user, got %s", all[0].From)
	}
	if all[len(all)-1].From != "agentA" || all[len(all)-1].Epoch != 4 {
		t.Errorf("newest should be merger agentA epoch=4")
	}
}

// --- extractInteractionsFromEnvelopes ---

func TestExtractInteractions_Linear(t *testing.T) {
	// user → agentA → agentB → agentA
	// last block (agentA) != initiator (user) → final edge agentA→user is added
	user := &workflowEnvelope{From: "user", Payload: "start", Epoch: 1, Code: 1000}
	agentA1 := &workflowEnvelope{From: "agentA", Payload: "delegate", Epoch: 2, Code: 1000, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Payload: "reply", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA1}}
	agentA2 := &workflowEnvelope{From: "agentA", Payload: "final", Epoch: 4, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentB}}

	ixs := extractInteractionsFromEnvelopes(agentA2)
	// Edges: user→agentA, agentA→agentB, agentB→agentA, + final agentA→user
	if len(ixs) != 4 {
		t.Fatalf("expected 4 interactions, got %d", len(ixs))
	}
	if ixs[0].FromDID != "user" || ixs[0].ToDID != "agentA" {
		t.Errorf("ixs[0] wrong: %s→%s", ixs[0].FromDID, ixs[0].ToDID)
	}
	if ixs[0].Type != "trigger" {
		t.Errorf("ixs[0] type: expected trigger, got %s", ixs[0].Type)
	}
	if ixs[1].Type != "delegate" {
		t.Errorf("ixs[1] type: expected delegate, got %s", ixs[1].Type)
	}
	if ixs[2].Type != "response" {
		t.Errorf("ixs[2] type: expected response, got %s", ixs[2].Type)
	}
	// Final closing edge
	if ixs[3].FromDID != "agentA" || ixs[3].ToDID != "user" {
		t.Errorf("ixs[3] final edge wrong: %s→%s", ixs[3].FromDID, ixs[3].ToDID)
	}
}

func TestExtractInteractions_Linear_SameInitiator(t *testing.T) {
	// user → agentA → user (last block's From == initiator → no final edge added)
	user1 := &workflowEnvelope{From: "user", Payload: "start", Epoch: 1, Code: 1000}
	agentA := &workflowEnvelope{From: "agentA", Payload: "work", Epoch: 2, Code: 1000, ParentEnvelope: []*workflowEnvelope{user1}}
	user2 := &workflowEnvelope{From: "user", Payload: "done", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA}}

	ixs := extractInteractionsFromEnvelopes(user2)
	// Edges: user→agentA, agentA→user — no extra final edge (last.From == initiator)
	if len(ixs) != 2 {
		t.Fatalf("expected 2 interactions, got %d", len(ixs))
	}
	if ixs[0].FromDID != "user" || ixs[0].ToDID != "agentA" {
		t.Errorf("ixs[0] wrong: %s→%s", ixs[0].FromDID, ixs[0].ToDID)
	}
	if ixs[1].FromDID != "agentA" || ixs[1].ToDID != "user" {
		t.Errorf("ixs[1] wrong: %s→%s", ixs[1].FromDID, ixs[1].ToDID)
	}
}

func TestExtractInteractions_Parallel(t *testing.T) {
	// user → agentA → agentB (branch1)
	//              → agentC (branch2)
	//       agentB, agentC → agentA (merger)
	// last block (agentA) != initiator (user) → final edge agentA→user added
	user := &workflowEnvelope{From: "user", Epoch: 1, Code: 1000}
	agentA1 := &workflowEnvelope{From: "agentA", Epoch: 2, Code: 1000, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA1}}
	agentC := &workflowEnvelope{From: "agentC", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA1}}
	merger := &workflowEnvelope{From: "agentA", Epoch: 4, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentB, agentC}}

	ixs := extractInteractionsFromEnvelopes(merger)
	// 5 edges + 1 final (agentA→user)
	if len(ixs) != 6 {
		t.Fatalf("expected 6 interactions, got %d", len(ixs))
	}

	type pair struct{ from, to string }
	got := map[pair]bool{}
	for _, ix := range ixs {
		got[pair{ix.FromDID, ix.ToDID}] = true
	}
	expected := []pair{
		{"user", "agentA"},
		{"agentA", "agentB"},
		{"agentA", "agentC"},
		{"agentB", "agentA"},
		{"agentC", "agentA"},
		{"agentA", "user"}, // final closing edge
	}
	for _, p := range expected {
		if !got[p] {
			t.Errorf("missing edge %s→%s", p.from, p.to)
		}
	}
}

func TestExtractInteractions_ThreatDetection(t *testing.T) {
	// user → agentA(threat) → agentB
	// last block (agentB) != initiator (user) → final edge agentB→user added
	user := &workflowEnvelope{From: "user", Epoch: 1, Code: 1000}
	agentA := &workflowEnvelope{From: "agentA", Epoch: 2, Code: 2001, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Epoch: 3, Code: 0, ParentEnvelope: []*workflowEnvelope{agentA}}

	ixs := extractInteractionsFromEnvelopes(agentB)

	// 2 edges + 1 final (agentB→user)
	if len(ixs) != 3 {
		t.Fatalf("expected 3 interactions, got %d", len(ixs))
	}
	// ixs[0]: user→agentA, code=1000 → no threat
	if ixs[0].Threat {
		t.Error("ixs[0]: code=1000 should not be threat")
	}
	// ixs[1]: agentA→agentB, code=2001 → threat
	if !ixs[1].Threat {
		t.Error("ixs[1]: code=2001 should be threat")
	}
	// ixs[2]: final agentB→user, code=0 → no threat
	if ixs[2].FromDID != "agentB" || ixs[2].ToDID != "user" {
		t.Errorf("ixs[2] final edge wrong: %s→%s", ixs[2].FromDID, ixs[2].ToDID)
	}
	if ixs[2].Threat {
		t.Error("ixs[2]: code=0 should not be threat")
	}
}

func TestExtractInteractions_Nil(t *testing.T) {
	ixs := extractInteractionsFromEnvelopes(nil)
	if len(ixs) != 0 {
		t.Errorf("expected empty, got %d", len(ixs))
	}
}

// --- JSON round-trip ---

func TestParseIntentWorkflow_NewSchema(t *testing.T) {
	raw := `{
		"type": "intent_workflow",
		"version": "2.0",
		"envelope": {
			"from": "agentA",
			"payload": "final reply",
			"epoch": 1720000003,
			"status_code": 1000,
			"signature": "sig3",
			"parent_envelope": [{
				"from": "agentB",
				"payload": "delegated work",
				"epoch": 1720000002,
				"status_code": 1000,
				"signature": "sig2",
				"parent_envelope": [{
					"from": "user",
					"payload": "hello",
					"epoch": 1720000001,
					"status_code": 1000,
					"signature": "sig1"
				}]
			}]
		}
	}`

	wf, err := parseIntentWorkflow(raw)
	if err != nil {
		t.Fatalf("parseIntentWorkflow error: %v", err)
	}
	if wf.Envelope == nil {
		t.Fatal("envelope is nil")
	}

	ixs := extractInteractionsFromEnvelopes(wf.Envelope)
	// user→agentB, agentB→agentA, + final agentA→user (agentA != user)
	if len(ixs) != 3 {
		t.Fatalf("expected 3 interactions, got %d", len(ixs))
	}
	if ixs[0].FromDID != "user" || ixs[0].ToDID != "agentB" {
		t.Errorf("ixs[0]: expected user→agentB, got %s→%s", ixs[0].FromDID, ixs[0].ToDID)
	}
	if ixs[1].FromDID != "agentB" || ixs[1].ToDID != "agentA" {
		t.Errorf("ixs[1]: expected agentB→agentA, got %s→%s", ixs[1].FromDID, ixs[1].ToDID)
	}
	if ixs[2].FromDID != "agentA" || ixs[2].ToDID != "user" {
		t.Errorf("ixs[2]: expected agentA→user (final), got %s→%s", ixs[2].FromDID, ixs[2].ToDID)
	}
}
