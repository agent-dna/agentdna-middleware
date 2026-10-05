package handler

import "testing"

// raw_data must be the envelope exactly as received: original key order,
// whitespace, and fields the struct doesn't know about.
func TestEnvelopeRawJSONIsVerbatim(t *testing.T) {
	parentRaw := `{"status_code":1000,  "from":"user","unknown_field":{"x":1},"payload":"hi","epoch":1,"parent_envelope":[]}`
	rootRaw := `{ "from" : "agentA", "epoch":2, "payload":"go", "extra":true, "parent_envelope":[` + parentRaw + `] }`
	data := `{"id":"nft1","envelope":` + rootRaw + `}`

	wf, err := parseIntentWorkflow(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(envelopeRawJSON(wf.Envelope)); got != rootRaw {
		t.Errorf("root raw changed:\n got %s\nwant %s", got, rootRaw)
	}
	if got := string(envelopeRawJSON(wf.Envelope.ParentEnvelope[0])); got != parentRaw {
		t.Errorf("parent raw changed:\n got %s\nwant %s", got, parentRaw)
	}
	if wf.Envelope.From != "agentA" || wf.Envelope.ParentEnvelope[0].Code != 1000 {
		t.Errorf("decoded columns wrong: %+v", wf.Envelope)
	}

	ixs := extractInteractionsFromEnvelopes(wf.Envelope, "user", "user")
	if len(ixs) == 0 || string(ixs[0].RawData) != parentRaw {
		t.Errorf("interaction raw_data not verbatim: %+v", ixs)
	}
}
