package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Ix is one stored new_interactions row.
type Ix struct {
	ID, From, To, Type, ThreatID, Message, Sig, Hash string
	Threat                                           bool
	RawLen                                           int
}

type IntentRow struct {
	Initiator, InitiatorName, Status, Flow, Executor string
	Threat                                           bool
	Depth                                            int
	IDs                                              []string
}

type ThreatRow struct {
	ID, BlockID, Message string
	Code                 int
}

type PendingRow struct {
	ReqID    string
	Inserted []string
	Renamed  []struct{ From, To string }
}

type AgentRow struct {
	Name, Deployer, Org, Policy, NFTID string
}

type Counts struct {
	Intents, Interactions, Threats, Pending, Agents int
}

func (h *Harness) Interactions(intentID string) ([]Ix, error) {
	rows, err := h.db.Query(`
		SELECT interaction_id, initiator_did, interacted_to_did, COALESCE(type,''), threat,
		       COALESCE(threat_id,''), COALESCE(message,''), COALESCE(signature,''), COALESCE(hash,''),
		       length(raw_data::text)
		FROM new_interactions WHERE intent_id = $1 ORDER BY interaction_id`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ix
	for rows.Next() {
		var x Ix
		var threat int
		if err := rows.Scan(&x.ID, &x.From, &x.To, &x.Type, &threat, &x.ThreatID, &x.Message, &x.Sig, &x.Hash, &x.RawLen); err != nil {
			return nil, err
		}
		x.Threat = threat == 1
		out = append(out, x)
	}
	return out, rows.Err()
}

// Intent returns nil (and no error) when the intent row doesn't exist.
func (h *Harness) Intent(intentID string) (*IntentRow, error) {
	var r IntentRow
	var threat int
	var ids string
	err := h.db.QueryRow(`
		SELECT COALESCE(initiator_did,''), COALESCE(initiator_name,''), COALESCE(status,''), threat_detected,
		       COALESCE(flow_type,''), COALESCE(executor,''), COALESCE(chain_depth,0), COALESCE(interaction_ids,'[]')
		FROM new_intents WHERE intent_id = $1`, intentID).
		Scan(&r.Initiator, &r.InitiatorName, &r.Status, &threat, &r.Flow, &r.Executor, &r.Depth, &ids)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Threat = threat == 1
	if err := json.Unmarshal([]byte(ids), &r.IDs); err != nil {
		return nil, fmt.Errorf("interaction_ids is not a JSON array: %q", ids)
	}
	return &r, nil
}

func (h *Harness) Threats(intentID string) ([]ThreatRow, error) {
	rows, err := h.db.Query(`SELECT id, interaction_id, threat_code, message FROM threats WHERE intent_id = $1 ORDER BY id`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ThreatRow
	for rows.Next() {
		var t ThreatRow
		if err := rows.Scan(&t.ID, &t.BlockID, &t.Code, &t.Message); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (h *Harness) Pending(intentID string) ([]PendingRow, error) {
	rows, err := h.db.Query(`SELECT req_id, payload FROM pending_branches WHERE intent_id = $1 ORDER BY req_id`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingRow
	for rows.Next() {
		var p PendingRow
		var payload string
		if err := rows.Scan(&p.ReqID, &payload); err != nil {
			return nil, err
		}
		var decoded struct {
			InsertedIDs []string `json:"insertedIds"`
			Renamed     []struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"renamed"`
		}
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
			return nil, fmt.Errorf("pending %s payload: %v", p.ReqID, err)
		}
		p.Inserted = decoded.InsertedIDs
		for _, r := range decoded.Renamed {
			p.Renamed = append(p.Renamed, struct{ From, To string }{r.From, r.To})
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (h *Harness) Agent(did string) (*AgentRow, error) {
	var a AgentRow
	err := h.db.QueryRow(`
		SELECT COALESCE(name,''), COALESCE(deployer_did,''), COALESCE(organization_id,''), COALESCE(policy,''), COALESCE(nft_id,'')
		FROM new_agents WHERE did = $1`, did).Scan(&a.Name, &a.Deployer, &a.Org, &a.Policy, &a.NFTID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &a, err
}

func (h *Harness) ToolAgents(toolDID string) ([]string, error) {
	var raw string
	if err := h.db.QueryRow(`SELECT COALESCE(agents_list,'[]') FROM new_tools WHERE did = $1`, toolDID).Scan(&raw); err != nil {
		return nil, err
	}
	var list []string
	err := json.Unmarshal([]byte(raw), &list)
	return list, err
}

func (h *Harness) CountAll() (Counts, error) {
	var c Counts
	err := h.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM new_intents), (SELECT COUNT(*) FROM new_interactions),
		(SELECT COUNT(*) FROM threats), (SELECT COUNT(*) FROM pending_branches), (SELECT COUNT(*) FROM new_agents)`).
		Scan(&c.Intents, &c.Interactions, &c.Threats, &c.Pending, &c.Agents)
	return c, err
}

func (h *Harness) CountIntentsByInitiator(did string) (int, error) {
	var n int
	err := h.db.QueryRow(`SELECT COUNT(*) FROM new_intents WHERE initiator_did = $1`, did).Scan(&n)
	return n, err
}

// CheckInvariants verifies the stored state of one intent is internally
// consistent, whatever path produced it. fails are data-integrity violations;
// warns are drift the dashboard tolerates (e.g. it re-derives the value).
func (h *Harness) CheckInvariants(intentID string) (fails, warns []string) {
	rows, err := h.Interactions(intentID)
	if err != nil {
		return []string{"read interactions: " + err.Error()}, nil
	}
	intent, err := h.Intent(intentID)
	if err != nil {
		return []string{"read intent: " + err.Error()}, nil
	}
	threats, err := h.Threats(intentID)
	if err != nil {
		return []string{"read threats: " + err.Error()}, nil
	}
	pending, err := h.Pending(intentID)
	if err != nil {
		return []string{"read pending: " + err.Error()}, nil
	}

	stored := map[string]Ix{}
	for _, r := range rows {
		stored[r.ID] = r
	}

	if intent == nil {
		if len(rows) > 0 {
			fails = append(fails, fmt.Sprintf("%d interaction row(s) exist but the intent row is gone (orphans: %s)", len(rows), idList(rows)))
		}
		if len(threats) > 0 {
			fails = append(fails, fmt.Sprintf("%d threat row(s) left behind for an intent that no longer exists", len(threats)))
		}
	} else {
		listed := map[string]bool{}
		for _, id := range intent.IDs {
			if listed[id] {
				fails = append(fails, "interaction_ids lists "+id+" twice")
			}
			listed[id] = true
		}
		var notStored, notListed []string
		for id := range listed {
			if _, ok := stored[id]; !ok {
				notStored = append(notStored, id)
			}
		}
		for id := range stored {
			if !listed[id] {
				notListed = append(notListed, id)
			}
		}
		if len(notStored) > 0 || len(notListed) > 0 {
			sort.Strings(notStored)
			sort.Strings(notListed)
			fails = append(fails, fmt.Sprintf("new_intents.interaction_ids out of sync with new_interactions: listed-but-missing=%v stored-but-unlisted=%v", notStored, notListed))
		}
		anyThreat := false
		for _, r := range rows {
			anyThreat = anyThreat || r.Threat
		}
		if intent.Threat != anyThreat {
			warns = append(warns, fmt.Sprintf("new_intents.threat_detected=%v but the stored interactions say %v (intent-list shows the stale column)", intent.Threat, anyThreat))
		}
	}

	linked := map[string]bool{}
	for _, r := range rows {
		if r.ThreatID != "" {
			linked[r.ThreatID] = true
		}
	}
	threatIDs := map[string]bool{}
	for _, t := range threats {
		threatIDs[t.ID] = true
		if !linked[t.ID] && intent != nil {
			fails = append(fails, fmt.Sprintf("orphan threat row %s (code %d) is not linked to any interaction — still counted by threat queries", t.ID, t.Code))
		}
	}
	for _, r := range rows {
		if r.ThreatID != "" && !threatIDs[r.ThreatID] {
			fails = append(fails, fmt.Sprintf("interaction %s links missing threat %s", r.ID, r.ThreatID))
		}
		if r.Threat && r.ThreatID == "" {
			warns = append(warns, fmt.Sprintf("interaction %s is flagged as a threat but has no threat row", r.ID))
		}
	}

	for _, p := range pending {
		for _, id := range p.Inserted {
			if _, ok := stored[id]; !ok {
				fails = append(fails, fmt.Sprintf("pending branch %s tracks %s, which no longer exists under that id — a /signature failure can't roll it back", p.ReqID, id))
			}
		}
	}

	fails = append(fails, checkHopIDs(intentID, rows)...)
	return fails, warns
}

// checkHopIDs validates the "<intent>-N" / "<intent>-P-L-M" id scheme: ids
// parse, trunk positions are contiguous from 1, no trunk row sits at or after
// a fork position, and every branch's offsets are contiguous from 1.
func checkHopIDs(intentID string, rows []Ix) []string {
	var fails []string
	trunk := map[int]bool{}
	branches := map[int]map[string][]int{}
	for _, r := range rows {
		rest, ok := strings.CutPrefix(r.ID, intentID+"-")
		if !ok {
			fails = append(fails, "interaction id "+r.ID+" doesn't start with its intent id")
			continue
		}
		parts := strings.Split(rest, "-")
		switch len(parts) {
		case 1:
			n, err := strconv.Atoi(parts[0])
			if err != nil {
				fails = append(fails, "unparseable hop id "+r.ID)
				continue
			}
			trunk[n] = true
		case 3:
			p, e1 := strconv.Atoi(parts[0])
			o, e2 := strconv.Atoi(parts[2])
			if e1 != nil || e2 != nil {
				fails = append(fails, "unparseable hop id "+r.ID)
				continue
			}
			if branches[p] == nil {
				branches[p] = map[string][]int{}
			}
			branches[p][parts[1]] = append(branches[p][parts[1]], o)
		default:
			fails = append(fails, "unparseable hop id "+r.ID)
		}
	}
	for n := 1; n <= len(trunk); n++ {
		if !trunk[n] {
			fails = append(fails, fmt.Sprintf("trunk has a gap: %s-%d missing", intentID, n))
			break
		}
	}
	for p, letters := range branches {
		for n := 1; n < p; n++ {
			if !trunk[n] {
				fails = append(fails, fmt.Sprintf("branches fork at position %d but trunk hop %s-%d (the shared prefix) is missing", p, intentID, n))
				break
			}
		}
		for n := range trunk {
			if n >= p {
				fails = append(fails, fmt.Sprintf("trunk row %s-%d coexists with a fork at position %d", intentID, n, p))
			}
		}
		for letter, offs := range letters {
			sort.Ints(offs)
			for i, o := range offs {
				if o != i+1 {
					fails = append(fails, fmt.Sprintf("branch %s-%d-%s offsets not contiguous: %v", intentID, p, letter, offs))
					break
				}
			}
		}
	}
	return fails
}

func idList(rows []Ix) string {
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return strings.Join(ids, ", ")
}
