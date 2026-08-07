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
	// First should be oldest (epoch 1 = user)
	if all[0].From != "user" {
		t.Errorf("oldest should be user, got %s", all[0].From)
	}
	// Last should be merger (epoch 4)
	if all[len(all)-1].From != "agentA" || all[len(all)-1].Epoch != 4 {
		t.Errorf("newest should be merger agentA epoch=4")
	}
}

// --- extractInteractionsFromEnvelopes ---

func TestExtractInteractions_Linear(t *testing.T) {
	// user → agentA → agentB → agentA (reply) → user (final)
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
	// Final: agentA → user
	last := ixs[len(ixs)-1]
	if last.FromDID != "agentA" || last.ToDID != "user" {
		t.Errorf("final edge wrong: %s→%s", last.FromDID, last.ToDID)
	}
}

func TestExtractInteractions_Parallel(t *testing.T) {
	// user → agentA → agentB (branch1)
	//              → agentC (branch2)
	//       agentB, agentC → agentA (merger) [final reply → user]
	user := &workflowEnvelope{From: "user", Epoch: 1, Code: 1000}
	agentA1 := &workflowEnvelope{From: "agentA", Epoch: 2, Code: 1000, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA1}}
	agentC := &workflowEnvelope{From: "agentC", Epoch: 3, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentA1}}
	merger := &workflowEnvelope{From: "agentA", Epoch: 4, Code: 1000, ParentEnvelope: []*workflowEnvelope{agentB, agentC}}

	ixs := extractInteractionsFromEnvelopes(merger)
	// Edges: user→agentA, agentA→agentB, agentA→agentC, agentB→agentA, agentC→agentA + final agentA→user
	if len(ixs) != 6 {
		t.Fatalf("expected 6 interactions (5 edges + 1 final), got %d", len(ixs))
	}

	// Collect from→to pairs for assertion (order may vary for parallel branches)
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
		{"agentA", "user"}, // final
	}
	for _, p := range expected {
		if !got[p] {
			t.Errorf("missing edge %s→%s", p.from, p.to)
		}
	}
}

func TestExtractInteractions_ThreatDetection(t *testing.T) {
	user := &workflowEnvelope{From: "user", Epoch: 1, Code: 1000}
	agentA := &workflowEnvelope{From: "agentA", Epoch: 2, Code: 2001, ParentEnvelope: []*workflowEnvelope{user}}
	agentB := &workflowEnvelope{From: "agentB", Epoch: 3, Code: 0, ParentEnvelope: []*workflowEnvelope{agentA}}

	ixs := extractInteractionsFromEnvelopes(agentB)

	// ixs[0]: edge user→agentA, threat comes from user envelope code=1000 → no threat
	if ixs[0].Threat {
		t.Error("ixs[0]: code=1000 should not be threat")
	}
	// ixs[1]: edge agentA→agentB, threat from agentA envelope code=2001 → threat
	if !ixs[1].Threat {
		t.Error("ixs[1]: code=2001 should be threat")
	}
	// final: agentB→user, from agentB code=0 → no threat
	last := ixs[len(ixs)-1]
	if last.Threat {
		t.Error("final: code=0 should not be threat")
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
		"version": "1.0",
		"envelope": {
			"from_": "agentA",
			"payload": "final reply",
			"epoch": 1720000003,
			"status_code": 1000,
			"signature": "sig3",
			"parent_envelope": [{
				"from_": "agentB",
				"payload": "delegated work",
				"epoch": 1720000002,
				"status_code": 1000,
				"signature": "sig2",
				"parent_envelope": [{
					"from_": "user",
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
	if len(ixs) != 3 {
		t.Fatalf("expected 3 interactions, got %d", len(ixs))
	}
	// user→agentB, agentB→agentA, agentA→user (final)
	if ixs[0].FromDID != "user" || ixs[0].ToDID != "agentB" {
		t.Errorf("ixs[0]: expected user→agentB, got %s→%s", ixs[0].FromDID, ixs[0].ToDID)
	}
	if ixs[2].FromDID != "agentA" || ixs[2].ToDID != "user" {
		t.Errorf("ixs[2]: expected agentA→user, got %s→%s", ixs[2].FromDID, ixs[2].ToDID)
	}
}
