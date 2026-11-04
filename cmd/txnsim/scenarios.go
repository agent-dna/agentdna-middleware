package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

func allScenarios() []Scenario {
	return []Scenario{
		{"H01", "happy", "agent_nft registers and updates an agent", scAgentRegistration},
		{"H02", "happy", "simple intent: user → agent → app, confirmed", scSimpleIntent},
		{"H03", "happy", "dashboard shows the confirmed intent to its user", scDashboardVisibility},
		{"H04", "happy", "intent started from the user's older DID", scOlderDID},
		{"H05", "happy", "COCA threat (2001) is recorded and linked", scThreatCOCA},
		{"H06", "happy", "CBAC guard threat takes its reason from the CBAC service", scThreatCBACReason},
		{"H07", "happy", "OK codes are not threats; non-guard code 4001 is", scThreatCodes},
		{"H08", "happy", "forks of one intent: branches a/b/c/d + exact replay", scForkLifecycle},
		{"H09", "happy", "fan-in DAG (parallel agents converge)", scFanIn},

		{"E01", "edge", "agent_nft validation and parentNFTId fallback", scAgentValidation},
		{"E02", "edge", "CBAC lookup fallbacks (404, bad JSON, success=false, empty)", scCBACFallbacks},
		{"E03", "edge", "payload shapes: content blocks, unicode, JSON object, 64KB", scPayloadShapes},
		{"E04", "edge", "same intent growing one hop per txn", scSequentialGrowth},
		{"E05", "edge", "identical epochs give a deterministic hop order", scEpochTies},
		{"E06", "edge", "100-hop chain", scLongChain},
		{"E07", "edge", "intent without data.id is rejected", scMissingID},
		{"E08", "edge", "intent with unsigned envelopes is rejected", scUnsignedReplay},
		{"E09", "edge", "malformed NFT data is forwarded unstored; a null envelope is rejected", scMalformed},
		{"E10", "edge", "non-NFT traffic passes through the proxy untouched", scPassthrough},
		{"E11", "edge", "a tx carrying two NFTs", scMultipleNFTs},
		{"E12", "edge", "txns naming an unregistered DID are rejected", scUnregisteredActor},

		{"F01", "failure", "/tx status=false rolls back a new intent", scTxFailNew},
		{"F02", "failure", "/tx status=false rolls back a fork and restores the trunk", scTxFailFork},
		{"F03", "failure", "/signature failure modes roll back the txn", scSigFailureModes},
		{"F04", "failure", "/signature failure on a fork restores the trunk", scSigFailFork},
		{"F05", "failure", "/signature response that isn't JSON", scSigNonJSON},
		{"F06", "failure", "txn that is never signed", scNeverSigned},
		{"F07", "failure", "/signature for an unknown request id", scSigUnknownID},
		{"F08", "failure", "/signature failure replayed after a confirmation", scSigReplay},
		{"F09", "failure", "Rubix node unreachable during /tx", scNodeDown},
		{"F10", "failure", "Rubix node answers /tx with HTTP 500", scNode500},
		{"F11", "failure", "Rubix node answers /tx with non-JSON", scTxNonJSON},
		{"F12", "failure", "Rubix node answers /tx without result.id", scTxEmptyID},
		{"F13", "failure", "earlier txn's signature fails after a later txn forked it", scInterleavedRollback},
		{"F14", "failure", "rolled-back txn leaves no threat rows (new intent)", scThreatRollbackNew},
		{"F15", "failure", "rolled-back threatening fork clears the intent's threat flag", scThreatRollbackFork},
		{"F16", "failure", "both branches of a fork fail their signature in turn", scBothBranchesFail},

		{"C01", "concurrency", "30 different intents in parallel", scParallelIntents},
		{"C02", "concurrency", "8 forks of one intent in parallel", scParallelForks},
	}
}

// ── Shared helpers ────────────────────────────────────────────────────────────

type pair struct{ From, To string }

func (p pair) String() string { return shortDID(p.From) + "→" + shortDID(p.To) }

// submit sends a tx (and, when sigBehavior != "", its /signature) and checks
// the body reached the Rubix node byte-for-byte.
// expectRejected submits an intent txn the middleware must refuse as
// malformed: 400 naming the problem, never forwarded, nothing stored.
func (t *T) expectRejected(what string, body []byte, wantMsg string) {
	before := t.counts()
	res := t.h.SendTx(body, "")
	t.Must(res.Err, "POST /rubix/v1/tx")
	t.Check(res.Code == http.StatusBadRequest && bytes.Contains(res.Body, []byte(wantMsg)),
		"%s: want 400 mentioning %q, got HTTP %d %.200s", what, wantMsg, res.Code, res.Body)
	t.Check(!t.h.rubix.Received(http.MethodPost, "/rubix/v1/tx", body), "%s: the node received a rejected tx", what)
	t.Equal(what+": rows created", t.counts(), before)
}

func (t *T) submit(body []byte, txBehavior, sigBehavior string) TxResult {
	res := t.h.SendTx(body, txBehavior)
	if res.Err != nil {
		t.Fatalf("POST /rubix/v1/tx: %v", res.Err)
	}
	if !t.h.rubix.Received(http.MethodPost, "/rubix/v1/tx", body) {
		t.Failf("the Rubix node never received this tx body unmodified")
	}
	if sigBehavior != "" {
		if res.ReqID == "" {
			t.Fatalf("tx returned no result.id to sign (HTTP %d, body %.200s)", res.Code, res.Body)
		}
		code, b, err := t.h.SendSig(res.ReqID, sigBehavior)
		if err != nil {
			t.Fatalf("POST /rubix/v1/signature: %v", err)
		}
		if code != http.StatusOK {
			t.Failf("signature passthrough returned HTTP %d: %.200s", code, b)
		}
	}
	return res
}

// intent submits an intent_workflow NFT whose newest envelope is root.
func (t *T) intent(nft, executor string, root *Env, txBehavior, sigBehavior string) TxResult {
	t.Track(nft)
	return t.submit(TxBody(executor, NFT{ID: nft, Data: IntentNFTData(nft, root)}), txBehavior, sigBehavior)
}

func (t *T) rows(intentID string) []Ix {
	rows, err := t.h.Interactions(intentID)
	t.Must(err, "read interactions")
	return rows
}

func (t *T) intentRow(intentID string) *IntentRow {
	r, err := t.h.Intent(intentID)
	t.Must(err, "read intent")
	return r
}

func (t *T) threats(intentID string) []ThreatRow {
	r, err := t.h.Threats(intentID)
	t.Must(err, "read threats")
	return r
}

func (t *T) pending(intentID string) []PendingRow {
	r, err := t.h.Pending(intentID)
	t.Must(err, "read pending_branches")
	return r
}

func (t *T) counts() Counts {
	c, err := t.h.CountAll()
	t.Must(err, "count rows")
	return c
}

// expectRows checks the exact set of interaction ids and their endpoints.
func (t *T) expectRows(intentID string, want map[string]pair) bool {
	got := map[string]pair{}
	for _, r := range t.rows(intentID) {
		got[r.ID] = pair{r.From, r.To}
	}
	var missing, extra, wrong []string
	for id, p := range want {
		g, ok := got[id]
		switch {
		case !ok:
			missing = append(missing, id+" "+p.String())
		case g != p:
			wrong = append(wrong, fmt.Sprintf("%s is %s, want %s", id, g, p))
		}
	}
	for id, g := range got {
		if _, ok := want[id]; !ok {
			extra = append(extra, id+" "+g.String())
		}
	}
	if len(missing)+len(extra)+len(wrong) == 0 {
		return true
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(wrong)
	t.Failf("stored hops differ from expected:\n  missing:    %v\n  unexpected: %v\n  wrong:      %v", missing, extra, wrong)
	return false
}

// expectPairs checks the stored hops as a multiset of from→to, ignoring ids.
func (t *T) expectPairs(intentID, context string, want []pair) bool {
	var got []string
	for _, r := range t.rows(intentID) {
		got = append(got, pair{r.From, r.To}.String())
	}
	var w []string
	for _, p := range want {
		w = append(w, p.String())
	}
	sort.Strings(got)
	sort.Strings(w)
	if strings.Join(got, ",") == strings.Join(w, ",") {
		return true
	}
	t.Failf("%s:\n  stored hops: %v\n  expected:    %v", context, got, w)
	return false
}

// expectGone checks nothing of intentID survived (rows, intent, threats,
// pending tracking).
func (t *T) expectGone(intentID, context string) bool {
	rows := t.rows(intentID)
	in := t.intentRow(intentID)
	th := t.threats(intentID)
	pd := t.pending(intentID)
	if len(rows) == 0 && in == nil && len(th) == 0 && len(pd) == 0 {
		return true
	}
	t.Failf("%s, but data survived: %d interaction(s) [%s], intent row=%v, %d threat row(s), %d pending row(s)",
		context, len(rows), idList(rows), in != nil, len(th), len(pd))
	return false
}

func trunkIDs(intentID string, n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%s-%d", intentID, i+1)
	}
	return ids
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

// ── Happy paths ───────────────────────────────────────────────────────────────

func scAgentRegistration(t *T) {
	U := t.h.user.DID
	did := t.DID("agent-x")
	nft := t.NFT("agent-x")
	t.submit(TxBody(U, NFT{ID: nft, Data: AgentNFTData(did, "Sim Agent X", U, simOrgID, "allow: read-only")}), "", "ok")

	a, err := t.h.Agent(did)
	t.Must(err, "read agent")
	if a == nil {
		t.Fatalf("agent %s was not registered", shortDID(did))
	}
	t.Equal("agent name", a.Name, "Sim Agent X")
	t.Equal("deployer_did", a.Deployer, U)
	t.Equal("organization_id", a.Org, simOrgID)
	t.Equal("policy", a.Policy, "allow: read-only")
	t.Equal("nft_id", a.NFTID, nft)

	t.submit(TxBody(U, NFT{ID: nft, Data: AgentNFTData(did, "Sim Agent X v2", U, simOrgID, "allow: everything")}), "", "ok")
	a, err = t.h.Agent(did)
	t.Must(err, "read agent")
	t.Equal("agent name after re-registration", a.Name, "Sim Agent X v2")
	t.Equal("policy after re-registration", a.Policy, "allow: everything")
}

func scSimpleIntent(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent-a"), t.h.toolDID
	b := t.Builder("main")
	u := b.Root(U, Payload("Book a meeting with the team for Friday"))
	a := b.Next(u, A, Payload("checking the team's calendars"))
	x := b.Next(a, tool, Payload("Friday 3pm is free for everyone"))
	nft := t.NFT("intent")

	res := t.intent(nft, U, x, "", "ok")
	t.Check(res.Code == http.StatusOK && res.OK, "tx passthrough: HTTP %d status=%v", res.Code, res.OK)

	t.expectRows(nft, map[string]pair{nft + "-1": {U, A}, nft + "-2": {A, tool}, nft + "-3": {tool, U}})
	rows := t.rows(nft)
	if len(rows) == 3 {
		t.Equal("hop types", []string{rows[0].Type, rows[1].Type, rows[2].Type}, []string{"trigger", "delegate", "response"})
		t.Equal("hop messages", []string{rows[0].Message, rows[1].Message, rows[2].Message}, []string{u.Text(), a.Text(), x.Text()})
		for _, r := range rows {
			t.Check(r.RawLen > len(r.Sig) && r.Sig != "", "hop %s: raw_data/signature not stored (raw %d bytes, sig %q)", r.ID, r.RawLen, r.Sig)
			t.Check(!r.Threat, "hop %s flagged as a threat", r.ID)
		}
	}

	in := t.intentRow(nft)
	if in == nil {
		t.Fatalf("intent row not created")
	}
	t.Equal("initiator_did", in.Initiator, U)
	t.Equal("initiator_name", in.InitiatorName, t.h.user.Name)
	t.Equal("status", in.Status, "completed")
	t.Equal("executor", in.Executor, U)
	t.Equal("chain_depth", in.Depth, 3)
	t.Equal("flow_type", in.Flow, "external_trigger")
	t.Equal("threat_detected", in.Threat, false)
	t.Equal("pending rows after confirmation", len(t.pending(nft)), 0)

	for _, did := range []string{U, tool} {
		ag, err := t.h.Agent(did)
		t.Must(err, "read agent")
		t.Check(ag == nil, "%s was wrongly registered as an agent", shortDID(did))
	}
	list, err := t.h.ToolAgents(tool)
	t.Must(err, "read tool agents_list")
	t.Check(contains(list, A), "tool agents_list %v doesn't include %s", list, shortDID(A))
}

func scDashboardVisibility(t *T) {
	U := t.h.user.DID
	nft := t.NFT("intent")
	t.intent(nft, U, t.Builder("main").Chain(U, t.Actor("agent"), t.h.toolDID), "", "ok")

	d, err := t.h.Login(t.h.user.Email, t.h.user.Password)
	t.Must(err, "dashboard login")
	sess, err := d.Get("/dashboard/v1/session")
	t.Must(err, "GET /session")
	t.Equal("session did", sess["did"], U)
	t.Equal("session is_admin", sess["is_admin"], false)

	entry := findIntent(t, d, nft)
	if entry == nil {
		t.Fatalf("intent %s not in the user's intent-list", nft)
	}
	t.Equal("intent-list interactionsCount", entry["interactionsCount"], float64(3))
	t.Equal("intent-list threatDetected", entry["threatDetected"], false)
	t.Equal("intent-list initiatorName", entry["initiatorName"], t.h.user.Name)

	info, err := d.Get("/dashboard/v1/intent-info?intentID=" + nft)
	t.Must(err, "GET /intent-info")
	ix, _ := info["interactions"].([]any)
	t.Equal("intent-info interactions", len(ix), 3)
	t.Equal("intent-info initiatorDID", info["initiatorDID"], U)
}

// findIntent pages through the caller's intent-list looking for intentID.
func findIntent(t *T, d *Dashboard, intentID string) map[string]any {
	for page := 1; page <= 20; page++ {
		data, err := d.Get(fmt.Sprintf("/dashboard/v1/intent-list?page=%d", page))
		t.Must(err, "GET /intent-list")
		list, _ := data["intentsList"].([]any)
		for _, it := range list {
			if m, ok := it.(map[string]any); ok && m["intentID"] == intentID {
				return m
			}
		}
		if len(list) == 0 {
			return nil
		}
	}
	return nil
}

func scOlderDID(t *T) {
	old := t.h.user.OldDID
	nft := t.NFT("intent")
	t.intent(nft, old, t.Builder("main").Chain(old, t.Actor("agent"), t.h.toolDID), "", "ok")

	ag, err := t.h.Agent(old)
	t.Must(err, "read agent")
	t.Check(ag == nil, "the user's older DID was auto-registered as an agent")
	if in := t.intentRow(nft); t.Check(in != nil, "intent not stored") {
		t.Equal("initiator_name for older DID", in.InitiatorName, t.h.user.Name)
	}

	d, err := t.h.Login(t.h.user.Email, t.h.user.Password)
	t.Must(err, "dashboard login")
	t.Check(findIntent(t, d, nft) != nil, "intent started from the older DID is missing from the user's intent-list")

	info, err := d.Get("/dashboard/v1/user-info?userID=" + old)
	t.Must(err, "GET /user-info by older DID")
	user, _ := info["user"].(map[string]any)
	t.Equal("user-info userID (primary DID)", user["userID"], t.h.user.DID)
	dids, _ := user["dids"].([]any)
	t.Equal("user-info dids", dids, []any{old, t.h.user.DID})
}

func scThreatCOCA(t *T) {
	U, A, tool := t.h.user.DID, t.Actor("agent-a"), t.h.toolDID
	b := t.Builder("main")
	u := b.Root(U)
	a := b.Next(u, A, Code(2001), Payload("Agent A is not whitelisted in Admin server"))
	x := b.Next(a, tool)
	nft := t.NFT("intent")
	t.intent(nft, U, x, "", "ok")

	th := t.threats(nft)
	if !t.Equal("threat rows", len(th), 1) {
		return
	}
	t.Equal("threat code", th[0].Code, 2001)
	t.Equal("threat message", th[0].Message, a.Text())
	rows := t.rows(nft)
	if t.Equal("hops", len(rows), 3) {
		t.Equal("threat flags per hop", []bool{rows[0].Threat, rows[1].Threat, rows[2].Threat}, []bool{false, true, false})
		t.Equal("threatening hop links the threat row", rows[1].ThreatID, th[0].ID)
	}
	if in := t.intentRow(nft); in != nil {
		t.Equal("intent threat_detected", in.Threat, true)
	}
}

func scThreatCBACReason(t *T) {
	U, A := t.h.user.DID, t.Actor("agent-a")
	b := t.Builder("main")
	hash := "cbac-ok-" + t.h.tag
	a := b.Next(b.Root(U), A, Code(3202), Payload(hash))
	nft := t.NFT("intent")
	t.intent(nft, U, b.Next(a, t.h.toolDID), "", "ok")

	th := t.threats(nft)
	if t.Equal("threat rows", len(th), 1) {
		t.Equal("threat message comes from the CBAC service", th[0].Message, cbacReason)
	}
	for _, r := range t.rows(nft) {
		if r.Threat && r.Message == hash {
			t.Warnf("the interaction's message is the CBAC hash %q, so the dashboard shows a hash instead of readable text for this hop", hash)
		}
	}
}

func scThreatCodes(t *T) {
	U, tool := t.h.user.DID, t.h.toolDID
	b := t.Builder("main")
	a := b.Next(b.Root(U), t.Actor("a"), Code(1000))
	bb := b.Next(a, t.Actor("b"), Code(0))
	c := b.Next(bb, t.Actor("c"), Code(4001), Payload("MCP tool execution failed: timeout after 30s"))
	nft := t.NFT("intent")
	t.intent(nft, U, b.Next(c, tool), "", "ok")

	th := t.threats(nft)
	if t.Equal("threat rows (only code 4001)", len(th), 1) {
		t.Equal("threat code", th[0].Code, 4001)
		t.Equal("non-guard threat message is the payload", th[0].Message, c.Text())
	}
	var flags []bool
	for _, r := range t.rows(nft) {
		flags = append(flags, r.Threat)
	}
	t.Equal("threat flags per hop", flags, []bool{false, false, false, true, false})
}

func scForkLifecycle(t *T) {
	U, A, B := t.h.user.DID, t.Actor("a"), t.Actor("b")
	X, Y, Z, W := t.Actor("x"), t.Actor("y"), t.Actor("z"), t.Actor("w")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	x, y, z := b.Next(bb, X), b.Next(bb, Y), b.Next(bb, Z)
	w := b.Next(y, W)
	n := t.NFT("intent")

	t.intent(n, U, x, "", "ok")
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, X}, n + "-4": {X, U}})

	t.intent(n, U, y, "", "ok")
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B},
		n + "-3-a-1": {B, X}, n + "-3-a-2": {X, U}, n + "-3-b-1": {B, Y}, n + "-3-b-2": {Y, U}})

	t.intent(n, U, z, "", "ok")
	t.intent(n, U, w, "", "ok")
	final := map[string]pair{n + "-1": {U, A}, n + "-2": {A, B},
		n + "-3-a-1": {B, X}, n + "-3-a-2": {X, U}, n + "-3-b-1": {B, Y}, n + "-3-b-2": {Y, U},
		n + "-3-c-1": {B, Z}, n + "-3-c-2": {Z, U},
		n + "-3-d-1": {B, Y}, n + "-3-d-2": {Y, W}, n + "-3-d-3": {W, U}}
	t.expectRows(n, final)
	t.Notef("continuing branch b (…→Y→W) starts a new branch d that repeats hop B→Y — only one level of branching is modelled")

	before := t.counts()
	res := t.intent(n, U, x, "", "ok") // exact replay of the first txn
	t.Check(res.OK, "replayed tx should still pass through to the node")
	after := t.counts()
	t.Equal("interactions after an exact replay", after.Interactions, before.Interactions)
	t.Equal("pending rows after an exact replay", after.Pending, before.Pending)
	t.expectRows(n, final)
}

func scFanIn(t *T) {
	U, A, B, C := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("c")
	b := t.Builder("main")
	u := b.Root(U)
	a, bb := b.Next(u, A), b.Next(u, B)
	c := b.Join([]*Env{a, bb}, C)
	n := t.NFT("intent")
	t.intent(n, U, c, "", "ok")

	t.expectPairs(n, "fan-in hops", []pair{{U, A}, {U, B}, {A, C}, {B, C}, {C, U}})
	var ids []string
	for _, r := range t.rows(n) {
		ids = append(ids, r.ID)
	}
	t.Equal("fan-in hop ids", sortedCopy(ids), sortedCopy(trunkIDs(n, 5)))
	if in := t.intentRow(n); in != nil && in.Depth != 4 {
		t.Warnf("chain_depth=%d for a DAG of 4 distinct envelopes: the shared root is serialised under both branches and counted twice", in.Depth)
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func scAgentValidation(t *T) {
	U := t.h.user.DID
	cases := []struct{ name, deployer, org, agentName string }{
		{"no-deployer", "", simOrgID, "Agent"},
		{"no-org", U, "", "Agent"},
		{"no-name", U, simOrgID, ""},
	}
	for _, c := range cases {
		did := t.DID(c.name)
		res := t.submit(TxBody(U, NFT{ID: t.NFT(c.name), Data: AgentNFTData(did, c.agentName, c.deployer, c.org, "p")}), "", "")
		t.Check(res.Code == http.StatusOK, "%s: tx not passed through (HTTP %d)", c.name, res.Code)
		ag, err := t.h.Agent(did)
		t.Must(err, "read agent")
		t.Check(ag == nil, "%s: invalid agent_nft was stored anyway", c.name)
	}

	did, parent := t.DID("parent-only"), t.NFT("parent")
	t.submit(TxBody(U, NFT{ParentID: parent, Data: AgentNFTData(did, "Parent Agent", U, simOrgID, "p")}), "", "ok")
	ag, err := t.h.Agent(did)
	t.Must(err, "read agent")
	if t.Check(ag != nil, "agent_nft with only parentNFTId was not stored") {
		t.Equal("nft_id falls back to parentNFTId", ag.NFTID, parent)
	}
}

func scCBACFallbacks(t *T) {
	U := t.h.user.DID
	b := t.Builder("main")
	a := b.Next(b.Root(U), t.Actor("a"), Code(3303), Payload("cbac-404-"+t.h.tag))
	bb := b.Next(a, t.Actor("b"), Code(3101), Payload("cbac-bad-"+t.h.tag))
	c := b.Next(bb, t.Actor("c"), Code(3001), Payload(nil))
	d := b.Next(c, t.Actor("d"), Code(3405), Payload("cbac-false-"+t.h.tag))
	n := t.NFT("intent")
	t.intent(n, U, b.Next(d, t.h.toolDID), "", "ok")

	got := map[int]string{}
	for _, th := range t.threats(n) {
		got[th.Code] = th.Message
	}
	for _, code := range []int{3303, 3101, 3001, 3405} {
		want := t.h.threatTitles[code]
		t.Check(want != "", "threat_codes has no title for %d", code)
		t.Equal(fmt.Sprintf("code %d falls back to the seeded title", code), got[code], want)
	}
}

func scPayloadShapes(t *T) {
	U := t.h.user.DID
	b := t.Builder("main")
	u := b.Root(U, Payload([]map[string]any{{"type": "image", "url": "https://x/y.png"}, {"type": "text", "text": "Summarise the Q3 report"}}))
	a := b.Next(u, t.Actor("a"), Payload("नमस्ते 🌍 <script>alert('x')</script> \"quoted\" back\\slash\nnewline"))
	bb := b.Next(a, t.Actor("b"), Payload(map[string]any{"tool": "search", "args": map[string]any{"q": "agentdna"}}))
	big := strings.Repeat("0123456789abcdef", 4096) // 64 KiB
	c := b.Next(bb, t.Actor("c"), Payload(big))
	n := t.NFT("intent")
	t.intent(n, U, b.Next(c, t.h.toolDID), "", "ok")

	rows := t.rows(n)
	if !t.Equal("hops", len(rows), 5) {
		return
	}
	t.Equal("content-block payload → its text block", rows[0].Message, "Summarise the Q3 report")
	t.Equal("unicode/HTML payload stored verbatim", rows[1].Message, a.Text())
	t.Equal("object payload stored as its JSON", rows[2].Message, bb.Text())
	t.Equal("64KiB payload length", len(rows[3].Message), len(big))
}

func scSequentialGrowth(t *T) {
	U, A, B, C := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("c")
	b := t.Builder("main")
	a := b.Next(b.Root(U), A)
	bb := b.Next(a, B)
	c := b.Next(bb, C)
	n := t.NFT("intent")
	t.intent(n, U, a, "", "ok")
	t.intent(n, U, bb, "", "ok")
	t.intent(n, U, c, "", "ok")

	if t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2-a-1": {A, U},
		n + "-2-b-1": {A, B}, n + "-2-b-2": {B, U},
		n + "-2-c-1": {A, B}, n + "-2-c-2": {B, C}, n + "-2-c-3": {C, U}}) {
		t.Warnf("a conversation that grows by one hop per txn (U→A, then U→A→B, then U→A→B→C) is stored as 3 branches with A→B repeated, not as one 4-hop trunk: " +
			"each txn's closing response hop (…→U) differs from the next txn's, so every txn looks like a fork. Confirm this is the intended model")
	}
}

func scEpochTies(t *T) {
	U, A, B, C := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("c")
	ts := time.Now().Unix() - 600
	for i := 1; i <= 4; i++ {
		b := t.Builder(fmt.Sprintf("run%d", i))
		e := b.Root(U, AtEpoch(ts))
		e = b.Next(e, A, AtEpoch(ts))
		e = b.Next(e, B, AtEpoch(ts))
		e = b.Next(e, C, AtEpoch(ts))
		n := t.NFT(fmt.Sprintf("run%d", i))
		t.intent(n, U, e, "", "ok")
		t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, C}, n + "-4": {C, U}})
		if in := t.intentRow(n); in != nil {
			t.Equal(fmt.Sprintf("run %d initiator with tied epochs", i), in.Initiator, U)
		}
	}
}

func scLongChain(t *T) {
	U := t.h.user.DID
	actors := []string{U}
	for i := 1; i < 100; i++ {
		actors = append(actors, t.Actor(fmt.Sprintf("agent-%03d", i)))
	}
	n := t.NFT("intent")
	start := time.Now()
	t.intent(n, U, t.Builder("main").Chain(actors...), "", "ok")
	took := time.Since(start)

	t.Equal("hops stored", len(t.rows(n)), 100)
	t.Notef("100-hop txn ingested in %s", took.Round(time.Millisecond))
	switch {
	case took > 30*time.Second:
		t.Failf("100-hop txn took %s to ingest (limit 30s)", took)
	case took > 5*time.Second:
		t.Warnf("100-hop txn took %s to ingest — the agent waits this long on every /tx call", took)
	}
}

func scMissingID(t *T) {
	U := t.h.user.DID
	x := t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID)
	t.expectRejected("intent without data.id", TxBody(U, NFT{ID: t.NFT("noid"), Data: IntentNFTData("", x)}), "missing id")
}

func scUnsignedReplay(t *T) {
	U := t.h.user.DID
	b := t.Builder("main")
	x := b.Next(b.Next(b.Root(U, Unsigned()), t.Actor("a"), Unsigned()), t.h.toolDID, Unsigned())
	n := t.NFT("intent")
	t.Track(n)
	t.expectRejected("unsigned envelopes", TxBody(U, NFT{ID: n, Data: IntentNFTData(n, x)}), "has no signature")
}

func scMalformed(t *T) {
	U := t.h.user.DID
	before := t.counts()

	bad := TxBody(U, NFT{ID: t.NFT("garbage"), Data: "{not json"})
	res := t.submit(bad, "", "")
	t.Check(res.Code == http.StatusOK, "malformed NFT data: tx not passed through (HTTP %d)", res.Code)

	n := t.NFT("null-envelope")
	t.Track(n)
	t.expectRejected("null envelope", TxBody(U, NFT{ID: n, Data: mustJSON(map[string]any{"id": n, "type": "intent_workflow", "envelope": nil})}), "missing envelope")

	unknown := TxBody(U, NFT{ID: t.NFT("unknown-type"), Data: `{"type":"mystery_nft","x":1}`})
	t.submit(unknown, "", "")

	after := t.counts()
	t.Equal("intents created by malformed txns", after.Intents-before.Intents, 0)
	t.Equal("interactions created by malformed txns", after.Interactions-before.Interactions, 0)
}

func scPassthrough(t *T) {
	before := t.counts()
	cases := []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/rubix/v1/tx", []byte("hello rubix, not json")},
		{http.MethodPost, "/rubix/v1/tx", []byte{}},
		{http.MethodPost, "/rubix/v1/tx", []byte(`{"initiator":"x","tokens":{"nft":[]}}`)},
		{http.MethodPut, "/rubix/v1/custom", []byte(`{"a":1}`)},
		{http.MethodGet, "/rubix/v1/status", nil},
	}
	for _, c := range cases {
		code, _, err := t.h.do(c.method, c.path, nil, c.body)
		t.Must(err, c.method+" "+c.path)
		t.Check(code == http.StatusOK, "%s %s returned HTTP %d", c.method, c.path, code)
		t.Check(t.h.rubix.Received(c.method, c.path, c.body), "%s %s (%d-byte body) didn't reach the node unmodified", c.method, c.path, len(c.body))
	}
	after := t.counts()
	t.Equal("rows created by non-NFT traffic", after.Interactions+after.Intents, before.Interactions+before.Intents)
}

func scMultipleNFTs(t *T) {
	U, agent := t.h.user.DID, t.Actor("second-agent")
	n := t.NFT("intent")
	t.Track(n)
	x := t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID)
	body := TxBody(U,
		NFT{ID: n, Data: IntentNFTData(n, x)},
		NFT{ID: t.NFT("agent"), Data: AgentNFTData(agent, "Second Agent", U, simOrgID, "p")})
	t.submit(body, "", "ok")

	t.Equal("intent hops from nft[0]", len(t.rows(n)), 3)
	ag, err := t.h.Agent(agent)
	t.Must(err, "read agent")
	if ag == nil {
		t.Warnf("only tokens.nft[0] is processed: the agent_nft at index 1 was forwarded but never registered")
	}
}

// ── Failure paths ─────────────────────────────────────────────────────────────

func scTxFailNew(t *T) {
	U, A := t.h.user.DID, t.Actor("a")
	n := t.NFT("intent")
	res := t.intent(n, U, t.Builder("main").Chain(U, A, t.h.toolDID), "fail", "")
	t.Check(res.Code == http.StatusOK && !res.OK, "node's status=false should pass through (HTTP %d status=%v)", res.Code, res.OK)
	t.expectGone(n, "the node rejected the tx (status=false)")
	if ag, _ := t.h.Agent(A); ag == nil {
		t.Failf("the rollback removed agent %s, which was registered before the txn", shortDID(A))
	}
}

func scTxFailFork(t *T) {
	U, A, B, X, Y := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("x"), t.Actor("y")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	n := t.NFT("intent")
	t.intent(n, U, b.Next(bb, X), "", "ok")
	t.intent(n, U, b.Next(bb, Y), "fail", "")
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, X}, n + "-4": {X, U}})
}

func scSigFailureModes(t *T) {
	U := t.h.user.DID
	for _, mode := range []string{"fail", "no-children", "empty-child", "empty-txid"} {
		n := t.NFT(mode)
		t.intent(n, U, t.Builder(mode).Chain(U, t.Actor("a-"+mode), t.h.toolDID), "", mode)
		t.expectGone(n, fmt.Sprintf("signature answered %q", mode))
	}
}

func scSigFailFork(t *T) {
	U, A, B, X, Y := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("x"), t.Actor("y")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	n := t.NFT("intent")
	t.intent(n, U, b.Next(bb, X), "", "ok")
	t.intent(n, U, b.Next(bb, Y), "", "fail")
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, X}, n + "-4": {X, U}})
	t.Equal("pending rows", len(t.pending(n)), 0)
}

func scSigNonJSON(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "", "nonjson")
	rows, pd := t.rows(n), t.pending(n)
	t.Check(len(rows) == 3 && len(pd) == 1, "expected the txn to stay stored and pending (unknown outcome), got %d hops / %d pending", len(rows), len(pd))
	if in := t.intentRow(n); in != nil && in.Status == "completed" {
		t.Warnf("a txn whose signature outcome is unknown is shown as a completed intent, and pending_branches never expires, so nothing will ever resolve it")
	}
}

func scNeverSigned(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "", "")
	t.Equal("pending rows for an unsigned txn", len(t.pending(n)), 1)
	if in := t.intentRow(n); in != nil && in.Status == "completed" {
		t.Warnf("a txn that was never signed already shows as a completed intent on the dashboard; its pending_branches row has no expiry")
	}
}

func scSigUnknownID(t *T) {
	before := t.counts()
	code, _, err := t.h.SendSig("simreq-never-issued-"+t.h.tag, "fail")
	t.Must(err, "POST /rubix/v1/signature")
	t.Equal("HTTP status", code, http.StatusOK)
	t.Equal("row counts after a failure for an unknown id", t.counts(), before)
}

func scSigReplay(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	res := t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "", "ok")
	code, _, err := t.h.SendSig(res.ReqID, "fail")
	t.Must(err, "replayed signature")
	t.Equal("HTTP status", code, http.StatusOK)
	t.Equal("hops after a late failure for an already-confirmed txn", len(t.rows(n)), 3)
}

func scNodeDown(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	res := t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "drop", "")
	t.Equal("proxy status when the node drops the connection", res.Code, http.StatusBadGateway)
	t.expectGone(n, "the Rubix node never answered /tx (connection dropped) — the txn can't exist on chain")
}

func scNode500(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	res := t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "http500", "")
	t.Equal("proxy passes the node's HTTP 500 through", res.Code, http.StatusInternalServerError)
	t.expectGone(n, "the Rubix node failed /tx with HTTP 500")
}

func untrackedCheck(t *T, n, what string) {
	rows, pd := t.rows(n), t.pending(n)
	if len(rows) > 0 && len(pd) == 0 {
		t.Failf("%s: %d hop(s) stored but not tracked in pending_branches, so no later /signature can confirm or roll them back — they stay forever looking like a confirmed intent", what, len(rows))
	}
}

func scTxNonJSON(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	res := t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "nonjson", "")
	t.Equal("proxy status", res.Code, http.StatusOK)
	untrackedCheck(t, n, "node answered /tx with HTML")
}

func scTxEmptyID(t *T) {
	U := t.h.user.DID
	n := t.NFT("intent")
	t.intent(n, U, t.Builder("main").Chain(U, t.Actor("a"), t.h.toolDID), "empty-id", "")
	untrackedCheck(t, n, "node answered /tx status=true without result.id")
}

func scInterleavedRollback(t *T) {
	U, A, B, X, Y := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("x"), t.Actor("y")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	n := t.NFT("intent")

	first := t.intent(n, U, b.Next(bb, X), "", "") // submitted, not yet signed
	t.intent(n, U, b.Next(bb, Y), "", "ok")        // forks it and is confirmed
	code, _, err := t.h.SendSig(first.ReqID, "fail")
	t.Must(err, "late signature failure")
	t.Equal("HTTP status", code, http.StatusOK)

	t.expectPairs(n, "txn1's signature failed after txn2 (confirmed) had forked it: only txn2's path should remain",
		[]pair{{U, A}, {A, B}, {B, Y}, {Y, U}})
	// One path left, so it is stored as plain trunk again.
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, Y}, n + "-4": {Y, U}})
}

// scBothBranchesFail: txn1 is forked by txn2 while both are unsigned; txn1
// fails first (its shared prefix must stay for txn2), then txn2 fails too —
// nothing may be left behind.
func scBothBranchesFail(t *T) {
	U, A, B, X, Y := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("x"), t.Actor("y")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	n := t.NFT("intent")

	first := t.intent(n, U, b.Next(bb, X), "", "")
	second := t.intent(n, U, b.Next(bb, Y, Code(2002), Payload("heavy COCA check failed")), "", "")
	_, _, err := t.h.SendSig(first.ReqID, "fail")
	t.Must(err, "first signature failure")
	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, Y}, n + "-4": {Y, U}})
	_, _, err = t.h.SendSig(second.ReqID, "fail")
	t.Must(err, "second signature failure")
	t.expectGone(n, "both txns of the intent failed their signature")
	t.Equal("threat rows left", len(t.threats(n)), 0)
}

func scThreatRollbackNew(t *T) {
	U := t.h.user.DID
	b := t.Builder("main")
	a := b.Next(b.Root(U), t.Actor("a"), Code(2001), Payload("not whitelisted"))
	n := t.NFT("intent")
	t.intent(n, U, b.Next(a, t.h.toolDID), "", "fail")
	t.expectGone(n, "the threatening txn's signature failed")
}

func scThreatRollbackFork(t *T) {
	U, A, B, X, Y := t.h.user.DID, t.Actor("a"), t.Actor("b"), t.Actor("x"), t.Actor("y")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	n := t.NFT("intent")
	t.intent(n, U, b.Next(bb, X), "", "ok")
	t.intent(n, U, b.Next(bb, Y, Code(2002), Payload("heavy COCA check failed")), "", "fail")

	t.expectRows(n, map[string]pair{n + "-1": {U, A}, n + "-2": {A, B}, n + "-3": {B, X}, n + "-4": {X, U}})
	t.Equal("threat rows after the threatening branch was rolled back", len(t.threats(n)), 0)
	if in := t.intentRow(n); in != nil && in.Threat {
		t.Failf("new_intents.threat_detected is still 1 after the only threatening branch was rolled back — intent-list and threat counts keep flagging a clean intent")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func scParallelIntents(t *T) {
	const n = 30
	U, tool := t.h.user.DID, t.h.toolDID
	type job struct {
		nft  string
		body []byte
	}
	jobs := make([]job, n)
	for i := range jobs {
		nft := t.NFT(fmt.Sprintf("p%02d", i))
		x := t.Builder(fmt.Sprintf("p%02d", i)).Chain(U, t.Actor(fmt.Sprintf("agent-%02d", i)), tool)
		jobs[i] = job{nft, TxBody(U, NFT{ID: nft, Data: IntentNFTData(nft, x)})}
		t.Track(nft)
	}
	errs := runParallel(t.h, len(jobs), func(i int) []byte { return jobs[i].body })
	for _, e := range errs {
		t.Failf("%s", e)
	}
	for _, j := range jobs {
		if got := len(t.rows(j.nft)); got != 3 {
			t.Failf("%s: %d hops stored, want 3", j.nft, got)
		}
		if len(t.pending(j.nft)) != 0 {
			t.Failf("%s: still pending after confirmation", j.nft)
		}
	}
}

func scParallelForks(t *T) {
	const n = 8
	U, A, B := t.h.user.DID, t.Actor("a"), t.Actor("b")
	b := t.Builder("main")
	bb := b.Next(b.Next(b.Root(U), A), B)
	nft := t.NFT("intent")
	t.Track(nft)
	want := []pair{{U, A}, {A, B}}
	bodies := make([][]byte, n)
	for i := range bodies {
		X := t.Actor(fmt.Sprintf("x%d", i))
		bodies[i] = TxBody(U, NFT{ID: nft, Data: IntentNFTData(nft, b.Next(bb, X))})
		want = append(want, pair{B, X}, pair{X, U})
	}
	for _, e := range runParallel(t.h, n, func(i int) []byte { return bodies[i] }) {
		t.Failf("%s", e)
	}

	t.expectPairs(nft, "8 parallel forks of one intent", want)
	letters := map[string]int{}
	trunk := 0
	for _, r := range t.rows(nft) {
		parts := strings.Split(strings.TrimPrefix(r.ID, nft+"-"), "-")
		if len(parts) == 3 {
			letters[parts[1]]++
		} else {
			trunk++
		}
	}
	t.Equal("trunk hops", trunk, 2)
	t.Equal("distinct branches", len(letters), n)
	for l, c := range letters {
		t.Check(c == 2, "branch %s has %d hops, want 2", l, c)
	}
}

// runParallel submits n tx+signature pairs at once and returns any errors.
func runParallel(h *Harness, n int, body func(i int) []byte) []string {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res := h.SendTx(body(i), "")
			if res.Err != nil || res.ReqID == "" {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("job %d: tx failed: HTTP %d err=%v", i, res.Code, res.Err))
				mu.Unlock()
				return
			}
			if code, b, err := h.SendSig(res.ReqID, "ok"); err != nil || code != http.StatusOK {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("job %d: signature failed: HTTP %d err=%v %.120s", i, code, err, b))
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// scUnregisteredActor: every actor must be registered before it transacts. A
// txn naming an unknown DID anywhere — chain, initiator or executor — is
// refused with 403 before anything is stored or sent to the node.
func scUnregisteredActor(t *T) {
	U, A := t.h.user.DID, t.Actor("a")
	stranger := t.DID("stranger") // never registered
	before := t.counts()
	cases := []struct {
		name, executor string
		newest         *Env
	}{
		{"unregistered agent in the chain", U, t.Builder("agent").Chain(U, stranger, t.h.toolDID)},
		{"unregistered initiator", U, t.Builder("user").Chain(stranger, A)},
		{"unregistered executor", stranger, t.Builder("exec").Chain(U, A)},
	}
	for i, c := range cases {
		n := t.NFT(fmt.Sprintf("rejected-%d", i))
		t.Track(n)
		body := TxBody(c.executor, NFT{ID: n, Data: IntentNFTData(n, c.newest)})
		res := t.h.SendTx(body, "")
		t.Must(res.Err, "POST /rubix/v1/tx")
		t.Check(res.Code == http.StatusForbidden && bytes.Contains(res.Body, []byte("UNREGISTERED_ACTOR")) && bytes.Contains(res.Body, []byte(stranger)),
			"%s: want 403 UNREGISTERED_ACTOR naming %s, got HTTP %d %.200s", c.name, shortDID(stranger), res.Code, res.Body)
		t.Check(!t.h.rubix.Received(http.MethodPost, "/rubix/v1/tx", body), "%s: the node received a rejected tx", c.name)
	}
	t.Equal("rows created by rejected txns", t.counts(), before)
}
