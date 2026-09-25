package db

import (
	"time"

	"github.com/lib/pq"
)

// ObsHop is one interaction row resolved to its threat code/title, for the
// observability page's hop classification and gate logic. Same threat join
// GetThreatsByOrg uses (threats.id = new_interactions.threat_id) — note
// threats.interaction_id holds the block id, not the interaction id, so it
// must never be joined on directly.
type ObsHop struct {
	IntentID string
	From     string
	To       string
	Time     time.Time
	Threat   bool
	Code     int
	Title    string
}

// GetObservabilityHops returns every interaction for the org within the given
// time window. When onlyInitiatorDID is non-empty, results are restricted to
// interactions whose intent was started by that DID — the non-admin scope
// for the observability page.
func (d *DB) GetObservabilityHops(orgID string, since time.Time, onlyInitiatorDID string) ([]*ObsHop, error) {
	query := `
		SELECT ni.intent_id, ni.initiator_did, ni.interacted_to_did, ni.time, ni.threat,
		       COALESCE(t.threat_code, 0), COALESCE(tc.title, '')
		FROM new_interactions ni
		LEFT JOIN threats t ON t.id = ni.threat_id
		LEFT JOIN threat_codes tc ON tc.code = t.threat_code
		WHERE ni.time >= $1`
	args := []any{since}
	if onlyInitiatorDID != "" {
		query += ` AND ni.intent_id IN (SELECT intent_id FROM new_intents WHERE initiator_did = $2)`
		args = append(args, onlyInitiatorDID)
	}
	query += ` ORDER BY ni.time ASC`

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ObsHop
	for rows.Next() {
		h := &ObsHop{}
		var threatInt int
		if err := rows.Scan(&h.IntentID, &h.From, &h.To, &h.Time, &threatInt, &h.Code, &h.Title); err != nil {
			return nil, err
		}
		h.Threat = threatInt == 1
		result = append(result, h)
	}
	return result, nil
}

// ObsUser/ObsAgent/ObsApp are the lightweight org-scoped registries the
// observability page uses to classify a hop by lookup, never by DID prefix.

type ObsUser struct {
	Name  string
	Email string
}

func (d *DB) GetOrgUserRegistry(orgID string) (map[string]*ObsUser, error) {
	rows, err := d.conn.Query(
		`SELECT did, COALESCE(name,''), email FROM new_org_users
		 WHERE did IS NOT NULL AND did <> '' AND did <> 'none'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*ObsUser{}
	for rows.Next() {
		var did, name, email string
		if err := rows.Scan(&did, &name, &email); err != nil {
			return nil, err
		}
		out[did] = &ObsUser{Name: name, Email: email}
	}
	return out, nil
}

type ObsAgent struct {
	Name        string
	Revoked     bool
	DeployerDID string
}

func (d *DB) GetOrgAgentRegistry(orgID string) (map[string]*ObsAgent, error) {
	rows, err := d.conn.Query(
		`SELECT did, COALESCE(name,''), revoked, COALESCE(deployer_did,'') FROM new_agents`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*ObsAgent{}
	for rows.Next() {
		var did, name, deployer string
		var revoked bool
		if err := rows.Scan(&did, &name, &revoked, &deployer); err != nil {
			return nil, err
		}
		out[did] = &ObsAgent{Name: name, Revoked: revoked, DeployerDID: deployer}
	}
	return out, nil
}

type ObsApp struct {
	Name string
}

func (d *DB) GetOrgAppRegistry(orgID string) (map[string]*ObsApp, error) {
	rows, err := d.conn.Query(
		`SELECT did, COALESCE(name,'') FROM new_tools`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*ObsApp{}
	for rows.Next() {
		var did, name string
		if err := rows.Scan(&did, &name); err != nil {
			return nil, err
		}
		out[did] = &ObsApp{Name: name}
	}
	return out, nil
}

// GetIntentInitiators maps intent_id -> initiator_did for the given intent
// IDs, scoped to the org. Used to attribute an agent->app hop back to the
// user whose intent it belongs to (the hop's own From/To are agent/app DIDs,
// not the user).
func (d *DB) GetIntentInitiators(orgID string, intentIDs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(intentIDs) == 0 {
		return out, nil
	}
	rows, err := d.conn.Query(
		`SELECT intent_id, initiator_did FROM new_intents WHERE intent_id = ANY($1)`,
		pq.Array(intentIDs),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, initiator string
		if err := rows.Scan(&id, &initiator); err != nil {
			return nil, err
		}
		out[id] = initiator
	}
	return out, nil
}

// ObsIntentInfo carries the display fields the observability page needs for
// an intent: the derived title (same value IntentRecord.Title/titleFull use —
// the first interaction's message), review status and start time.
type ObsIntentInfo struct {
	Title        string
	ReviewStatus string
	StartedAt    time.Time
}

func (d *DB) GetObsIntentInfo(orgID string, intentIDs []string) (map[string]*ObsIntentInfo, error) {
	out := map[string]*ObsIntentInfo{}
	if len(intentIDs) == 0 {
		return out, nil
	}
	rows, err := d.conn.Query(
		`SELECT ni.intent_id,
		        COALESCE((SELECT message FROM new_interactions WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), ''),
		        COALESCE(ni.review_status, 'Ongoing'),
		        ni.started_at
		 FROM new_intents ni
		 WHERE ni.intent_id = ANY($1)`,
		pq.Array(intentIDs),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		info := &ObsIntentInfo{}
		var intentID string
		if err := rows.Scan(&intentID, &info.Title, &info.ReviewStatus, &info.StartedAt); err != nil {
			return nil, err
		}
		out[intentID] = info
	}
	return out, nil
}

// OrgUserExists checks whether the given DID belongs to a user in the org —
// used by observability-user-flow to 404 on an unknown userDID.
func (d *DB) OrgUserExists(orgID, did string) (bool, error) {
	var exists bool
	err := d.conn.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM new_org_users WHERE did = $1)`,
		did,
	).Scan(&exists)
	return exists, err
}
