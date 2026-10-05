package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

func (d *DB) StoreAdmin(did, orgID, apiKey, email, passwordHash string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_admins (did, organization_id, api_key, email, password)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (did) DO NOTHING`,
		did, orgID, apiKey, email, passwordHash,
	)
	return err
}

func (d *DB) GetAdminByEmail(email string) (*AdminRecord, error) {
	var a AdminRecord
	var orgID, apiKey sql.NullString
	err := d.conn.QueryRow(
		`SELECT did, organization_id, api_key, email, COALESCE(name,''), password FROM new_admins WHERE email = $1`, email,
	).Scan(&a.DID, &orgID, &apiKey, &a.Email, &a.Name, &a.PasswordHash)
	if err != nil {
		return nil, err
	}
	a.OrganizationID = orgID.String
	a.APIKey = apiKey.String
	return &a, nil
}

func (d *DB) GetAdminEmailByOrgID(orgID string) (name, email string, err error) {
	err = d.conn.QueryRow(
		`SELECT COALESCE(did,''), COALESCE(email,'') FROM new_admins WHERE organization_id = $1 LIMIT 1`,
		orgID,
	).Scan(&name, &email)
	return
}

func (d *DB) GetAllAdminEmailsByOrgID(orgID string) ([]string, error) {
	rows, err := d.conn.Query(
		`SELECT TRIM(email) FROM new_admins WHERE organization_id = $1 AND email IS NOT NULL AND TRIM(email) <> ''`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var emails []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err == nil && strings.TrimSpace(e) != "" {
			emails = append(emails, strings.TrimSpace(e))
		}
	}
	return emails, nil
}

func (d *DB) GetOrgUserEmailByDID(did string) (name, email string, err error) {
	err = d.conn.QueryRow(
		`SELECT COALESCE(name,''), COALESCE(email,'') FROM new_org_users WHERE did = $1`,
		did,
	).Scan(&name, &email)
	return
}

func (d *DB) GetAdminByDID(did string) (*AdminRecord, error) {
	var a AdminRecord
	var orgID, apiKey sql.NullString
	err := d.conn.QueryRow(
		`SELECT did, organization_id, api_key, email, password FROM new_admins WHERE did = $1`, did,
	).Scan(&a.DID, &orgID, &apiKey, &a.Email, &a.PasswordHash)
	if err != nil {
		return nil, err
	}
	a.OrganizationID = orgID.String
	a.APIKey = apiKey.String
	return &a, nil
}

func (d *DB) GetAdminByOrgID(orgID string) (*AdminRecord, error) {
	var a AdminRecord
	var apiKey sql.NullString
	err := d.conn.QueryRow(
		`SELECT did, organization_id, api_key, email, password FROM new_admins WHERE organization_id = $1 LIMIT 1`, orgID,
	).Scan(&a.DID, &a.OrganizationID, &apiKey, &a.Email, &a.PasswordHash)
	if err != nil {
		return nil, err
	}
	a.APIKey = apiKey.String
	return &a, nil
}

func (d *DB) CreateRequest(id, requestType, policy, creatorDID, agentDID, agentName, requestInfo, orgID string) error {
	_, err := d.conn.Exec(`
		INSERT INTO new_requests (request_id, request_type, policy, creator_did, agent_did, agent_name, request_info, organization_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, requestType, policy, creatorDID, agentDID, agentName, requestInfo, orgID,
	)
	return err
}

// ActiveRequestExistsForAgent returns true if a pending or approved deploy_agent
// request already exists for the given agent_did, meaning a new one should not be created.
func (d *DB) ActiveRequestExistsForAgent(agentDID string) (bool, error) {
	var exists bool
	err := d.conn.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM new_requests
			WHERE agent_did = $1
			  AND request_type = 'deploy_agent'
			  AND status IN ('pending', 'approved')
		)`, agentDID,
	).Scan(&exists)
	return exists, err
}

func (d *DB) GetRequestByID(id string) (*RequestRecord, error) {
	r := &RequestRecord{}
	var agentDID, agentName, requestInfo, orgID sql.NullString
	err := d.conn.QueryRow(`
		SELECT request_id, request_type, policy, creator_did, COALESCE(agent_did,''), COALESCE(agent_name,''),
		       COALESCE(request_info,''), COALESCE(organization_id,''), status, created_at
		FROM new_requests WHERE request_id = $1`, id,
	).Scan(&r.RequestID, &r.RequestType, &r.Policy, &r.CreatorDID,
		&agentDID, &agentName, &requestInfo, &orgID, &r.Status, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.AgentDID, r.AgentName, r.RequestInfo, r.OrgID = agentDID.String, agentName.String, requestInfo.String, orgID.String
	return r, nil
}

func (d *DB) GetAgentNameByRequestDID(agentDID string) (string, error) {
	var name string
	err := d.conn.QueryRow(
		`SELECT COALESCE(agent_name, '') FROM new_requests WHERE agent_did = $1 AND agent_name <> '' LIMIT 1`,
		agentDID,
	).Scan(&name)
	return name, err
}

func (d *DB) UpdateRequestStatus(id, status string) error {
	_, err := d.conn.Exec(`UPDATE new_requests SET status = $1 WHERE request_id = $2`, status, id)
	return err
}

func (d *DB) UpdateRequest(id, agentName, policy, requestInfo string) error {
	_, err := d.conn.Exec(`
		UPDATE new_requests SET agent_name = $1, policy = $2, request_info = $3
		WHERE request_id = $4 AND status = 'pending'`,
		agentName, policy, requestInfo, id,
	)
	return err
}

func (d *DB) GetRequestsByOrg(orgID, requestType string, limit, offset int) ([]*RequestRecord, error) {
	rows, err := d.conn.Query(`
		SELECT request_id, request_type, policy, creator_did,
		       COALESCE(agent_did,''), COALESCE(agent_name,''),
		       COALESCE(request_info,''), COALESCE(organization_id,''), status, created_at
		FROM new_requests
		WHERE organization_id = $1 AND request_type = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`,
		orgID, requestType, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequestRows(rows)
}

func (d *DB) CountRequestsByOrg(orgID, requestType string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_requests WHERE organization_id = $1 AND request_type = $2`,
		orgID, requestType,
	).Scan(&total)
	return total, err
}

// GetAllRequestsByOrg and CountAllRequestsByOrg return every request for the
// org regardless of request_type (deploy_agent, agent_access, ...) — used by
// endpoints that show the org's full request queue rather than one type at a
// time.
func (d *DB) GetAllRequestsByOrg(orgID string, limit, offset int) ([]*RequestRecord, error) {
	rows, err := d.conn.Query(`
		SELECT request_id, request_type, policy, creator_did,
		       COALESCE(agent_did,''), COALESCE(agent_name,''),
		       COALESCE(request_info,''), COALESCE(organization_id,''), status, created_at
		FROM new_requests
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequestRows(rows)
}

func (d *DB) CountAllRequestsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_requests WHERE organization_id = $1`,
		orgID,
	).Scan(&total)
	return total, err
}

// GetAllRequestsByUser and CountAllRequestsByUser are the creator_did-scoped
// counterparts, used for a non-admin caller's own request queue.
func (d *DB) GetAllRequestsByUser(creatorDID string, limit, offset int) ([]*RequestRecord, error) {
	rows, err := d.conn.Query(`
		SELECT request_id, request_type, policy, creator_did,
		       COALESCE(agent_did,''), COALESCE(agent_name,''),
		       COALESCE(request_info,''), COALESCE(organization_id,''), status, created_at
		FROM new_requests
		WHERE creator_did = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`,
		creatorDID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequestRows(rows)
}

func (d *DB) CountAllRequestsByUser(creatorDID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_requests WHERE creator_did = $1`,
		creatorDID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetRequestsByUser(creatorDID, requestType string, limit, offset int) ([]*RequestRecord, error) {
	rows, err := d.conn.Query(`
		SELECT request_id, request_type, policy, creator_did,
		       COALESCE(agent_did,''), COALESCE(agent_name,''),
		       COALESCE(request_info,''), COALESCE(organization_id,''), status, created_at
		FROM new_requests
		WHERE creator_did = $1 AND request_type = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`,
		creatorDID, requestType, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequestRows(rows)
}

func (d *DB) CountRequestsByUser(creatorDID, requestType string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_requests WHERE creator_did = $1 AND request_type = $2`,
		creatorDID, requestType,
	).Scan(&total)
	return total, err
}

func scanRequestRows(rows *sql.Rows) ([]*RequestRecord, error) {
	var result []*RequestRecord
	for rows.Next() {
		r := &RequestRecord{}
		if err := rows.Scan(&r.RequestID, &r.RequestType, &r.Policy, &r.CreatorDID,
			&r.AgentDID, &r.AgentName, &r.RequestInfo, &r.OrgID, &r.Status, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) UpdateAgentInfo(did, agentName, policy string) error {
	_, err := d.conn.Exec(
		`UPDATE new_agents SET policy = $1, name = $2 WHERE did = $3`,
		policy, agentName, did,
	)
	return err
}

func (d *DB) AddAgentToUserAccessList(userDID, agentDID string) error {
	// Read current list, append if not present, write back as JSON
	var raw string
	err := d.conn.QueryRow(`SELECT COALESCE(agent_access_list, '[]') FROM new_org_users WHERE did = $1`, userDID).Scan(&raw)
	if err != nil {
		return err
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		list = []string{}
	}
	for _, v := range list {
		if v == agentDID {
			return nil // already present
		}
	}
	list = append(list, agentDID)
	updated, err := json.Marshal(list)
	if err != nil {
		return err
	}
	_, err = d.conn.Exec(`UPDATE new_org_users SET agent_access_list = $1 WHERE did = $2`, string(updated), userDID)
	return err
}

func (d *DB) CountAgentsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM new_agents
		WHERE organization_id = $1
			AND did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1 AND did != 'none')`,
		orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetAgentsByOrg(orgID string, limit, offset int) ([]*AgentDetailRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			COALESCE(NULLIF(a.name, ''), ''),
			COALESCE(a.created_at, NOW()),
			COALESCE(a.deployer_did, ''),
			COALESCE(a.policy, ''),
			COUNT(i.interaction_id)                                              AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                       AS total_threats,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                  AS score
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1 AND did != 'none')
		GROUP BY a.did, a.name, a.created_at, a.deployer_did, a.policy
		ORDER BY a.did
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AgentDetailRecord
	for rows.Next() {
		r := &AgentDetailRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentName, &r.CreatedAt, &r.DeployerDID, &r.Policy,
			&r.TotalInteractions, &r.TotalThreats, &r.Score); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) CountAgentsByUser(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM new_agents a
		WHERE a.deployer_did = $1`,
		userDID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetAgentsByUser(userDID, orgID string, limit, offset int) ([]*AgentDetailRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			COALESCE(NULLIF(a.name, ''), ''),
			COALESCE(a.created_at, NOW()),
			COALESCE(a.deployer_did, ''),
			COALESCE(a.policy, ''),
			COUNT(i.interaction_id)                                              AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                       AS total_threats,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                  AS score
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.deployer_did = $1
		GROUP BY a.did, a.name, a.created_at, a.deployer_did, a.policy
		ORDER BY a.did
		LIMIT $2 OFFSET $3`,
		userDID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AgentDetailRecord
	for rows.Next() {
		r := &AgentDetailRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentName, &r.CreatedAt, &r.DeployerDID, &r.Policy,
			&r.TotalInteractions, &r.TotalThreats, &r.Score); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// userScopeIntentsCTE returns a CTE block that defines user_agents and user_intents
// for the given userDID ($1) and orgID ($2). Used across all user-scoped queries.
const userScopeIntentsCTE = `
WITH user_agents AS (
    SELECT a.did
    FROM new_agents a
    WHERE a.organization_id = $2
      AND (
          a.deployer_did = $1
          OR a.did IN (
              SELECT agent_did FROM new_requests
              WHERE creator_did = $1 AND request_type = 'deploy_agent' AND status = 'approved'
          )
          OR a.did IN (
              SELECT json_array_elements_text(COALESCE(u.agent_access_list,'[]')::json)
              FROM new_org_users u WHERE u.did = $1
          )
      )
),
user_intents AS (
    SELECT DISTINCT ni.intent_id, ni.started_at
    FROM new_intents ni
    LEFT JOIN new_interactions ix ON ix.intent_id = ni.intent_id
    WHERE ni.organization_id = $2
      AND (
          ni.initiator_did = $1
          OR ix.initiator_did = $1
          OR ix.initiator_did    IN (SELECT did FROM user_agents)
          OR ix.interacted_to_did IN (SELECT did FROM user_agents)
      )
)
`

func (d *DB) GetUserMetrics(userDID, orgID string) (*OrgMetrics, error) {
	m := &OrgMetrics{}
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)

	err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT
			(SELECT COUNT(*) FROM new_agents WHERE deployer_did = $1),
			(SELECT COUNT(*) FROM user_intents),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND intent_id IN (SELECT intent_id FROM user_intents)),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents)),
			(SELECT COUNT(DISTINCT t.did) FROM new_tools t
			 INNER JOIN new_interactions i
			         ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
			        AND i.organization_id = $2
			 WHERE i.intent_id IN (SELECT intent_id FROM user_intents)),
			(SELECT COUNT(*) FROM new_agents WHERE deployer_did = $1 AND created_at >= $3),
			(SELECT COUNT(*) FROM user_intents WHERE started_at >= $3),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND intent_id IN (SELECT intent_id FROM user_intents) AND time >= $3),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents) AND time >= $3),
			(SELECT COUNT(DISTINCT t.did) FROM new_tools t
			 INNER JOIN new_interactions i
			         ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
			        AND i.organization_id = $2
			 WHERE i.intent_id IN (SELECT intent_id FROM user_intents) AND i.time >= $3)
		`,
		userDID, orgID, twentyFourHoursAgo,
	).Scan(&m.AgentCount, &m.IntentCount, &m.InteractionsCount, &m.ThreatCount, &m.AppCount,
		&m.AgentCount24hChange, &m.IntentCount24hChange, &m.InteractionsCount24hChange, &m.ThreatCount24hChange, &m.AppCount24hChange)
	return m, err
}

func (d *DB) GetTopAgentsByUser(userDID, orgID string, limit, offset int) ([]*AgentVolumeRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT
			a.did,
			a.nft_id,
			COALESCE(NULLIF(a.name, ''), ''),
			COUNT(i.interaction_id)                          AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)   AS total_threats
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.did IN (SELECT did FROM user_agents)
		GROUP BY a.did, a.nft_id, a.name
		ORDER BY total_interactions DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*AgentVolumeRecord
	for rows.Next() {
		r := &AgentVolumeRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentNFTID, &r.AgentName, &r.TotalInteractions, &r.TotalThreats); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) CountIntentsByUser(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(userScopeIntentsCTE+`SELECT COUNT(*) FROM user_intents`,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetIntentsByUser(userDID, orgID string, limit, offset int) ([]*IntentRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT ni.intent_id, ni.initiator_did,
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, COALESCE(ni.review_status, 'Unreviewed'), ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(i.interaction_id)                                                  AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN i.interacted_to_did END) AS tools_count,
		       SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                           AS threat_count,
		       MIN(i.time)                                                               AS first_interaction_at,
		       MAX(i.time)                                                               AS last_interaction_at,
		       COALESCE((SELECT message FROM new_interactions
		        WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), '') AS title
		FROM new_intents ni
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		LEFT JOIN new_interactions i ON i.intent_id = ni.intent_id
		LEFT JOIN new_agents a ON a.did = i.interacted_to_did
		LEFT JOIN new_tools t ON t.did = i.interacted_to_did
		WHERE ni.intent_id IN (SELECT intent_id FROM user_intents)
		GROUP BY ni.intent_id, u.name, ag_init.name
		ORDER BY ni.started_at DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*IntentRecord
	for rows.Next() {
		r := &IntentRecord{}
		var endedAt, firstAt, lastAt sql.NullTime
		var threatInt int
		if err := rows.Scan(
			&r.IntentID, &r.InitiatorDID, &r.InitiatorName, &r.OrgID,
			&r.StartedAt, &endedAt, &r.Status, &r.ReviewStatus, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth,
			&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount, &r.ThreatCount,
			&firstAt, &lastAt, &r.Title,
		); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		if endedAt.Valid {
			r.EndedAt = &endedAt.Time
		}
		if firstAt.Valid {
			r.FirstInteractionAt = &firstAt.Time
		}
		if lastAt.Valid {
			r.LastInteractionAt = &lastAt.Time
			if firstAt.Valid {
				r.RuntimeSeconds = lastAt.Time.Sub(firstAt.Time).Seconds()
			}
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) CountInteractionsByUser(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(*) FROM new_interactions
		WHERE organization_id = $2 AND intent_id IN (SELECT intent_id FROM user_intents)`,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetInteractionsByUser(userDID, orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions
		WHERE organization_id = $2 AND intent_id IN (SELECT intent_id FROM user_intents)
		ORDER BY time DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func (d *DB) CountThreatsByUser(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(*) FROM new_interactions
		WHERE threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents)`,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetThreatsByUser(userDID, orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT ni.interaction_id,
		       ni.initiator_did, COALESCE(ni.initiator_name, ''),
		       ni.interacted_to_did, COALESCE(ni.interacted_to_name, ''),
		       COALESCE(ni.type, ''), COALESCE(ni.direction, ''), ni.threat, ni.intent_id, ni.time, COALESCE(t.message, ''),
		       COALESCE(ni.signature, ''), COALESCE(ni.threat_id, ''),
		       COALESCE(t.threat_code, 0), COALESCE(NULLIF(tc.title, ''), 'Unknown Threat'), COALESCE(nint.review_status, 'Unreviewed')
		FROM new_interactions ni
		LEFT JOIN threats t ON t.id = ni.threat_id
		LEFT JOIN threat_codes tc ON tc.code = t.threat_code
		LEFT JOIN new_intents nint ON nint.intent_id = ni.intent_id
		WHERE ni.threat = 1 AND ni.intent_id IN (SELECT intent_id FROM user_intents)
		ORDER BY ni.time DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRowsWithTitle(rows)
}

func (d *DB) CountUsersByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM new_org_users WHERE organization_id = $1`, orgID).Scan(&total)
	return total, err
}

func (d *DB) GetUsersByOrg(orgID string, limit, offset int) ([]*UserDetailRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			COALESCE(u.did, ''),
			COALESCE(u.name, ''),
			COALESCE(u.created_at, NOW()),
			COUNT(DISTINCT ni.intent_id)                                                AS total_intents,
			COUNT(DISTINCT CASE WHEN i.threat = 1 THEN i.interaction_id END)            AS total_threats,
			(SELECT COUNT(*) FROM json_array_elements_text(COALESCE(u.agent_access_list, '[]')::json)) AS access_agent_count
		FROM new_org_users u
		LEFT JOIN new_intents ni ON ni.initiator_did = u.did
		LEFT JOIN new_interactions i ON i.intent_id = ni.intent_id
		WHERE u.organization_id = $1
		GROUP BY u.did, u.email, u.created_at, u.agent_access_list
		ORDER BY u.did
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*UserDetailRecord
	for rows.Next() {
		r := &UserDetailRecord{}
		if err := rows.Scan(&r.UserDID, &r.UserName, &r.CreatedAt,
			&r.TotalIntents, &r.TotalThreats, &r.AccessAgentCount); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetInteractionsByOrg(orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions
		WHERE organization_id = $1
		ORDER BY time DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func (d *DB) CountInteractionsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1`, orgID).Scan(&total)
	return total, err
}

func (d *DB) CountInteractionsByOrgAndIntent(orgID, intentID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND intent_id = $2`,
		orgID, intentID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetInteractionsByOrgAndIntent(orgID, intentID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions
		WHERE organization_id = $1 AND intent_id = $2
		ORDER BY time ASC
		LIMIT $3 OFFSET $4`,
		orgID, intentID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func (d *DB) CountThreatsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE threat = 1`,
	).Scan(&total)
	return total, err
}

func (d *DB) GetThreatsByOrg(orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT ni.interaction_id,
		       ni.initiator_did, COALESCE(ni.initiator_name, ''),
		       ni.interacted_to_did, COALESCE(ni.interacted_to_name, ''),
		       COALESCE(ni.type, ''), COALESCE(ni.direction, ''), ni.threat, ni.intent_id, ni.time, COALESCE(t.message, ''),
		       COALESCE(ni.signature, ''), COALESCE(ni.threat_id, ''),
		       COALESCE(t.threat_code, 0), COALESCE(NULLIF(tc.title, ''), 'Unknown Threat'), COALESCE(nint.review_status, 'Unreviewed')
		FROM new_interactions ni
		LEFT JOIN threats t ON t.id = ni.threat_id
		LEFT JOIN threat_codes tc ON tc.code = t.threat_code
		LEFT JOIN new_intents nint ON nint.intent_id = ni.intent_id
		WHERE ni.threat = 1
		ORDER BY ni.time DESC
		LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRowsWithTitle(rows)
}

func (d *DB) CountTopThreatAgentsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT a.did)
		FROM new_agents a
		JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
			AND i.threat = 1
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1 AND did != 'none')`,
		orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetTopThreatAgentsByOrg(orgID string, limit, offset int) ([]*AgentVolumeRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			a.nft_id,
			COALESCE(NULLIF(a.name, ''), ''),
			COUNT(i.interaction_id)                        AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) AS total_threats
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1 AND did != 'none')
		GROUP BY a.did, a.nft_id, a.name
		ORDER BY total_threats DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AgentVolumeRecord
	for rows.Next() {
		r := &AgentVolumeRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentNFTID, &r.AgentName, &r.TotalInteractions, &r.TotalThreats); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetBottomAgentsByOrg(orgID string, limit, offset int) ([]*AgentVolumeRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			a.nft_id,
			COALESCE(NULLIF(a.name, ''), ''),
			COUNT(i.interaction_id)                          AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)   AS total_threats
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
		GROUP BY a.did, a.nft_id, a.name
		ORDER BY total_interactions ASC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AgentVolumeRecord
	for rows.Next() {
		r := &AgentVolumeRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentNFTID, &r.AgentName, &r.TotalInteractions, &r.TotalThreats); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetOrgMetrics(orgID string) (*OrgMetrics, error) {
	m := &OrgMetrics{}

	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_agents WHERE organization_id = $1`, orgID,
	).Scan(&m.AgentCount); err != nil {
		return nil, err
	}

	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_intents WHERE organization_id = $1`, orgID,
	).Scan(&m.IntentCount); err != nil {
		return nil, err
	}

	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1`, orgID,
	).Scan(&m.InteractionsCount); err != nil {
		return nil, err
	}

	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND threat = 1`, orgID,
	).Scan(&m.ThreatCount); err != nil {
		return nil, err
	}

	// Apps: distinct new_tools rows that have shown up on either side of at
	// least one interaction in this org.
	if err := d.conn.QueryRow(
		`SELECT COUNT(DISTINCT t.did) FROM new_tools t
		 INNER JOIN new_interactions i
		         ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		        AND i.organization_id = $1`,
		orgID,
	).Scan(&m.AppCount); err != nil {
		return nil, err
	}

	// Calculate 24-hour changes
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)

	// Agent count 24h change
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_agents WHERE organization_id = $1 AND created_at >= $2`,
		orgID, twentyFourHoursAgo,
	).Scan(&m.AgentCount24hChange); err != nil {
		return nil, err
	}

	// Intent count 24h change
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_intents WHERE organization_id = $1 AND started_at >= $2`,
		orgID, twentyFourHoursAgo,
	).Scan(&m.IntentCount24hChange); err != nil {
		return nil, err
	}

	// Interactions count 24h change
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND time >= $2`,
		orgID, twentyFourHoursAgo,
	).Scan(&m.InteractionsCount24hChange); err != nil {
		return nil, err
	}

	// Threat count 24h change
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND threat = 1 AND time >= $2`,
		orgID, twentyFourHoursAgo,
	).Scan(&m.ThreatCount24hChange); err != nil {
		return nil, err
	}

	// App count 24h change — distinct apps with at least one interaction in
	// the last 24h (new_tools has no created_at column to key off of).
	if err := d.conn.QueryRow(
		`SELECT COUNT(DISTINCT t.did) FROM new_tools t
		 INNER JOIN new_interactions i
		         ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		        AND i.organization_id = $1
		 WHERE i.time >= $2`,
		orgID, twentyFourHoursAgo,
	).Scan(&m.AppCount24hChange); err != nil {
		return nil, err
	}

	return m, nil
}

type GlobalStats struct {
	TotalUsers        int `json:"totalUsers"`
	TotalAgents       int `json:"totalAgents"`
	TotalInteractions int `json:"totalInteractions"`
	TotalIntents      int `json:"totalIntents"`
	TotalThreats      int `json:"totalThreats"`
}

func (d *DB) GetGlobalStats() (*GlobalStats, error) {
	s := &GlobalStats{}
	err := d.conn.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM new_org_users),
			(SELECT COUNT(*) FROM new_agents),
			(SELECT COUNT(*) FROM new_interactions),
			(SELECT COUNT(*) FROM new_intents),
			(SELECT COUNT(*) FROM new_interactions WHERE threat = 1)
	`).Scan(&s.TotalUsers, &s.TotalAgents, &s.TotalInteractions, &s.TotalIntents, &s.TotalThreats)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *DB) GetTopAgentsByOrg(orgID string, limit, offset int) ([]*AgentVolumeRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			a.nft_id,
			COALESCE(NULLIF(a.name, ''), ''),
			COUNT(i.interaction_id)                          AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)   AS total_threats
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1 AND did != 'none')
		GROUP BY a.did, a.nft_id, a.name
		ORDER BY total_interactions DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*AgentVolumeRecord
	for rows.Next() {
		r := &AgentVolumeRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentNFTID, &r.AgentName, &r.TotalInteractions, &r.TotalThreats); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

type UserProfile struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	DID            string `json:"did"`
	APIKey         string `json:"apiKey"`
	OrganizationID string `json:"organizationID"`
	CreatedAt      string `json:"createdAt"`
	AdminEmail     string `json:"adminEmail"`
}

func (d *DB) GetUserProfile(email string) (*UserProfile, error) {
	p := &UserProfile{}
	err := d.conn.QueryRow(`
		SELECT
			COALESCE(u.name, ''),
			u.email,
			COALESCE(u.did, ''),
			COALESCE(u.api_key, ''),
			COALESCE(u.organization_id, ''),
			COALESCE(u.created_at::TEXT, ''),
			COALESCE(a.email, '')
		FROM new_org_users u
		LEFT JOIN new_admins a ON a.organization_id = u.organization_id
		WHERE u.email = $1`,
		email,
	).Scan(&p.Name, &p.Email, &p.DID, &p.APIKey, &p.OrganizationID, &p.CreatedAt, &p.AdminEmail)
	if err != nil {
		return nil, err
	}
	return p, nil
}

type AdminProfile struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	DID            string `json:"did"`
	OrganizationID string `json:"organizationID"`
	APIKey         string `json:"apiKey"`
	AgentCount     int    `json:"agentCount"`
	IntentCount    int    `json:"intentCount"`
	ThreatCount    int    `json:"threatCount"`
	TotalUsers     int    `json:"totalUsers"`
	CreatedAt      int64  `json:"createdAt"`
}

func (d *DB) GetAdminProfile(username string) (*AdminProfile, error) {
	p := &AdminProfile{}
	var createdAt sql.NullTime
	err := d.conn.QueryRow(`
		SELECT
			COALESCE(name, ''),
			email,
			COALESCE(did, ''),
			COALESCE(organization_id, ''),
			COALESCE(api_key, ''),
			agent_count,
			intent_count,
			threat_count,
			total_users,
			created_at
		FROM new_admins
		WHERE did = $1`,
		username,
	).Scan(&p.Name, &p.Email, &p.DID, &p.OrganizationID, &p.APIKey, &p.AgentCount, &p.IntentCount, &p.ThreatCount, &p.TotalUsers, &createdAt)
	if err != nil {
		return nil, err
	}
	if createdAt.Valid {
		p.CreatedAt = createdAt.Time.Unix()
	}
	return p, nil
}

func (d *DB) GetOrgUserByEmail(email string) (*OrgUserRecord, error) {
	var u OrgUserRecord
	var (
		did, orgID, apiKey, nftID, passwordHash sql.NullString
		accessListRaw                           string
	)
	err := d.conn.QueryRow(`
		SELECT did, organization_id, api_key, nft_id, COALESCE(name, ''), email, password,
		       agent_count, intent_count, threat_count, COALESCE(agent_access_list, '[]')
		FROM new_org_users WHERE email = $1`, email,
	).Scan(&did, &orgID, &apiKey, &nftID, &u.Name, &u.Email, &passwordHash,
		&u.AgentCount, &u.IntentCount, &u.ThreatCount, &accessListRaw)
	if err != nil {
		return nil, err
	}
	u.DID = did.String
	u.OrganizationID = orgID.String
	u.APIKey = apiKey.String
	u.NFTID = nftID.String
	u.PasswordHash = passwordHash.String
	if err := json.Unmarshal([]byte(accessListRaw), &u.AgentAccessList); err != nil {
		u.AgentAccessList = []string{}
	}
	return &u, nil
}

func (d *DB) GetOrgUserByAPIKey(apiKey string) (*OrgUserRecord, error) {
	u := &OrgUserRecord{}
	var accessListJSON string
	err := d.conn.QueryRow(`
		SELECT did, organization_id, COALESCE(api_key,''), COALESCE(nft_id,''),
		       COALESCE(name,''), email, password, COALESCE(policy,''),
		       agent_count, intent_count, threat_count,
		       COALESCE(agent_access_list,'[]'), COALESCE(key,'')
		FROM new_org_users WHERE api_key = $1`,
		apiKey,
	).Scan(
		&u.DID, &u.OrganizationID, &u.APIKey, &u.NFTID,
		&u.Name, &u.Email, &u.PasswordHash, &u.Policy,
		&u.AgentCount, &u.IntentCount, &u.ThreatCount,
		&accessListJSON, &u.Key,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(accessListJSON), &u.AgentAccessList)
	return u, nil
}

func (d *DB) UpdateUserName(email, name string) error {
	res, err := d.conn.Exec(`UPDATE new_org_users SET name = $1 WHERE email = $2`, name, email)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) UpdateUserEmail(currentEmail, newEmail string) error {
	var exists bool
	d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_org_users WHERE email = $1)`, newEmail).Scan(&exists)
	if exists {
		return fmt.Errorf("email already in use")
	}
	res, err := d.conn.Exec(`UPDATE new_org_users SET email = $1 WHERE email = $2`, newEmail, currentEmail)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) UpdateUserDIDByAPIKey(apiKey, did string) error {
	_, err := d.conn.Exec(
		`UPDATE new_org_users SET did = $1 WHERE api_key = $2`,
		did, apiKey,
	)
	return err
}

func (d *DB) GetUserPolicy(did string) (string, error) {
	var policy string
	err := d.conn.QueryRow(
		`SELECT COALESCE(policy, '') FROM new_org_users WHERE did = $1`, did,
	).Scan(&policy)
	return policy, err
}

func (d *DB) UpdateUserPolicy(did, policy string) error {
	_, err := d.conn.Exec(
		`UPDATE new_org_users SET policy = $1 WHERE did = $2`, policy, did,
	)
	return err
}

func (d *DB) GetAgentPolicy(agentDID string) (string, error) {
	var policy string
	err := d.conn.QueryRow(
		`SELECT COALESCE(policy, '') FROM new_agents WHERE did = $1`, agentDID,
	).Scan(&policy)
	return policy, err
}

func (d *DB) UpdateAgentPolicy(did, policy string) error {
	_, err := d.conn.Exec(
		`UPDATE new_agents SET policy = $1 WHERE did = $2`, policy, did,
	)
	return err
}

func (d *DB) GetOrgUserNameByDID(did string) (string, error) {
	var name string
	err := d.conn.QueryRow(`SELECT COALESCE(name, '') FROM new_org_users WHERE did = $1`, did).Scan(&name)
	return name, err
}

func (d *DB) StoreOrgUser(orgID, name, email, passwordHash string) error {
	if name == "" {
		// Find the next available user_N name.
		var n int
		for {
			n++
			candidate := fmt.Sprintf("user_%d", n)
			var exists bool
			d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_org_users WHERE name = $1)`, candidate).Scan(&exists)
			if !exists {
				name = candidate
				break
			}
		}
	}

	_, err := d.conn.Exec(
		`INSERT INTO new_org_users (nft_id, did, organization_id, name, email, password) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
		"default-card-id", "default-id", orgID, name, email, passwordHash,
	)
	return err
}

// RegisterOrgUser creates a new user with a generated api_key and a temporary
// placeholder DID. The real DID is populated later via UpdateUserDIDByAPIKey.
func (d *DB) RegisterOrgUser(apiKey, orgID, name, email, passwordHash string) error {
	if name == "" {
		var n int
		for {
			n++
			candidate := fmt.Sprintf("user_%d", n)
			var exists bool
			d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_org_users WHERE name = $1)`, candidate).Scan(&exists)
			if !exists {
				name = candidate
				break
			}
		}
	}
	_, err := d.conn.Exec(
		`INSERT INTO new_org_users ( api_key, organization_id, name, email, password)
		 VALUES ($1, $2, $3, $4, $5)`,
		apiKey, orgID, name, email, passwordHash,
	)
	return err
}

func (d *DB) SetUserKey(did, key string) error {
	_, err := d.conn.Exec(
		`UPDATE new_org_users SET key = $1 WHERE did = $2`,
		key, did,
	)
	return err
}

func (d *DB) GetUserByKey(key string) (*OrgUserRecord, error) {
	u := &OrgUserRecord{}
	var accessListJSON string
	err := d.conn.QueryRow(
		`SELECT did, organization_id, COALESCE(api_key,''), COALESCE(nft_id,''),
		        COALESCE(name,''), email, password, COALESCE(policy,''),
		        agent_count, intent_count, threat_count,
		        COALESCE(agent_access_list,'[]'), COALESCE(key,'')
		 FROM new_org_users WHERE key = $1 LIMIT 1`,
		key,
	).Scan(
		&u.DID, &u.OrganizationID, &u.APIKey, &u.NFTID,
		&u.Name, &u.Email, &u.PasswordHash, &u.Policy,
		&u.AgentCount, &u.IntentCount, &u.ThreatCount,
		&accessListJSON, &u.Key,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(accessListJSON), &u.AgentAccessList)
	return u, nil
}

func (d *DB) CountAgentsWithNamePrefix(prefix string) (int, error) {
	var count int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM new_agents WHERE name LIKE $1`, prefix+"%").Scan(&count)
	return count, err
}

// StoreNewAgent inserts a placeholder agent row the first time an unknown DID
// is seen mid-workflow (no real NFT registration event for it yet). It never
// overwrites an existing row — if the DID is later registered properly via
// UpsertAgentFromNFT, that call must win, not this one.
func (d *DB) StoreNewAgent(nftID, did, deployerDID, orgID, policy, agentName string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_agents (nft_id, did, deployer_did, organization_id, policy, name) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
		nftID, did, deployerDID, orgID, policy, agentName,
	)
	return err
}

// UpsertAgentFromNFT records an agent from an authoritative source — the
// on-chain agent-NFT registration event (handleAgentNFT) or an admin-approved
// agent-creation request. Unlike StoreNewAgent, this always overwrites
// nft_id/deployer_did/organization_id/policy/name — it must win over any
// placeholder row StoreNewAgent created earlier for the same DID.
func (d *DB) UpsertAgentFromNFT(nftID, did, deployerDID, orgID, policy, agentName string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_agents (nft_id, did, deployer_did, organization_id, policy, name)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (did) DO UPDATE SET
		   nft_id          = EXCLUDED.nft_id,
		   deployer_did    = EXCLUDED.deployer_did,
		   organization_id = EXCLUDED.organization_id,
		   policy          = EXCLUDED.policy,
		   name            = EXCLUDED.name`,
		nftID, did, deployerDID, orgID, policy, agentName,
	)
	return err
}

func (d *DB) IsNewTool(did string) bool {
	var exists bool
	d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_tools WHERE did = $1)`, did).Scan(&exists)
	return exists
}

func (d *DB) RevokeAgent(agentDID string) error {
	res, err := d.conn.Exec(`UPDATE new_agents SET revoked = TRUE WHERE did = $1`, agentDID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", agentDID)
	}
	return nil
}

// UnrevokeAgent mirrors RevokeAgent — flips the agent's local revoked flag back
// to FALSE. Called from the unrevoke-agent endpoint.
func (d *DB) UnrevokeAgent(agentDID string) error {
	res, err := d.conn.Exec(`UPDATE new_agents SET revoked = FALSE WHERE did = $1`, agentDID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found: %s", agentDID)
	}
	return nil
}

func (d *DB) GetAgentOrgID(agentDID string) (string, error) {
	var orgID sql.NullString
	err := d.conn.QueryRow(`
		SELECT organization_id FROM new_agents WHERE did = $1
		UNION ALL
		SELECT organization_id FROM new_org_users WHERE did = $1
		UNION ALL
		SELECT organization_id FROM new_admins WHERE did = $1
		LIMIT 1`, agentDID).Scan(&orgID)
	return orgID.String, err
}

// GetAgentNFTIDByDID looks up a registered agent by its DID and returns the
// agent's nft_id. The bool reports whether an agent with that DID exists.
func (d *DB) GetAgentNFTIDByDID(agentDID string) (string, bool, error) {
	var nftID sql.NullString
	err := d.conn.QueryRow(`SELECT nft_id FROM new_agents WHERE did = $1`, agentDID).Scan(&nftID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return nftID.String, true, nil
}

func (d *DB) GetAgentNFTID(agentDID string) (string, error) {
	var nftID sql.NullString
	err := d.conn.QueryRow(`SELECT nft_id FROM new_agents WHERE did = $1`, agentDID).Scan(&nftID)
	return nftID.String, err
}

func (d *DB) StoreNewInteraction(id, initiatorDID, initiatorName, interactedToDID, interactedToName, interactionType, direction string, threat bool, intentID, orgID, message, signature, hash, threatID string, rawData json.RawMessage, eventTime time.Time) error {
	threatInt := 0
	if threat {
		threatInt = 1
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	if len(rawData) == 0 {
		rawData = json.RawMessage("{}")
	}
	_, err := d.conn.Exec(
		`INSERT INTO new_interactions
		 (interaction_id, initiator_did, initiator_name, interacted_to_did, interacted_to_name, type, direction, threat, intent_id, organization_id, message, signature, hash, threat_id, raw_data, time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT DO NOTHING`,
		id, initiatorDID, initiatorName, interactedToDID, interactedToName, interactionType, direction, threatInt, intentID, orgID, message, signature, hash, threatID, string(rawData), eventTime,
	)
	return err
}

// RenameInteractionID relabels an already-stored interaction row — used when a
// later txn reveals that a position previously thought to be plain trunk
// ("<intentID>-N") was actually the start of a fork, so it's retroactively
// relabeled into branch "a" ("<intentID>-N-a-1").
func (d *DB) RenameInteractionID(oldID, newID string) error {
	_, err := d.conn.Exec(`UPDATE new_interactions SET interaction_id = $1 WHERE interaction_id = $2`, newID, oldID)
	return err
}

// IntentHopRow is one stored hop of an intent (nftId), returned so the caller
// can reconstruct the trunk/branch tree by parsing interaction_id and compare
// against a new txn's hop sequence by (hash, from, to).
type IntentHopRow struct {
	InteractionID string
	Hash          string
	From, To      string
}

// GetIntentHops returns every stored hop for the given intent_id (nftId),
// across every branch, unordered — the caller sorts/classifies by parsing
// each InteractionID's numeric/branch suffix.
func (d *DB) GetIntentHops(intentID string) ([]IntentHopRow, error) {
	rows, err := d.conn.Query(
		`SELECT interaction_id, COALESCE(hash, ''), initiator_did, interacted_to_did FROM new_interactions WHERE intent_id = $1`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntentHopRow
	for rows.Next() {
		var r IntentHopRow
		if err := rows.Scan(&r.InteractionID, &r.Hash, &r.From, &r.To); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IntentExists reports whether an intent (nftId) has already been stored —
// the caller uses this to decide between inserting a brand-new new_intents
// row and merging into an existing one.
func (d *DB) IntentExists(intentID string) (bool, error) {
	var exists bool
	err := d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_intents WHERE intent_id = $1)`, intentID).Scan(&exists)
	return exists, err
}

func (d *DB) StoreIntent(intentID, initiatorDID, initiatorName, orgID, flowType, executor string, chainDepth int, threatDetected bool, interactionIDs []string) error {
	interactionIDsJSON, err := json.Marshal(interactionIDs)
	if err != nil {
		return err
	}
	threatInt := 0
	if threatDetected {
		threatInt = 1
	}
	_, err = d.conn.Exec(
		`INSERT INTO new_intents
		 (intent_id, initiator_did, initiator_name, organization_id, interaction_ids, status, threat_detected, flow_type, executor, chain_depth)
		 VALUES ($1, $2, $3, $4, $5, 'completed', $6, $7, $8, $9) ON CONFLICT DO NOTHING`,
		intentID, initiatorDID, initiatorName, orgID, string(interactionIDsJSON), threatInt, flowType, executor, chainDepth,
	)
	return err
}

// MergeIntentBranch folds a later txn's branch into an already-existing
// intent (nftId): the interaction_ids list, threat flag and chain depth all
// need to account for every branch now, not just the one this txn added.
func (d *DB) MergeIntentBranch(intentID string, chainDepth int, threatDetected bool, interactionIDs []string) error {
	interactionIDsJSON, err := json.Marshal(interactionIDs)
	if err != nil {
		return err
	}
	threatInt := 0
	if threatDetected {
		threatInt = 1
	}
	_, err = d.conn.Exec(
		`UPDATE new_intents
		 SET interaction_ids = $2,
		     threat_detected = CASE WHEN threat_detected = 1 THEN 1 ELSE $3 END,
		     chain_depth     = GREATEST(chain_depth, $4),
		     ended_at        = NOW()
		 WHERE intent_id = $1`,
		intentID, string(interactionIDsJSON), threatInt, chainDepth,
	)
	return err
}

// RenamedInteractionID records a trunk row relabeled into a branch when a
// later txn revealed its position was actually a fork point (e.g.
// "nft-3" -> "nft-3-a-1"). Kept so a failed /signature confirmation for the
// *new* branch can undo the relabel and restore the original trunk numbering.
type RenamedInteractionID struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// pendingBranchPayload is the JSON blob stored in pending_branches.payload.
type pendingBranchPayload struct {
	InsertedIDs []string               `json:"insertedIds"`
	Renamed     []RenamedInteractionID `json:"renamed"`
}

// InsertPendingBranch records, keyed by the /rubix/v1/tx response's result.id,
// exactly which interaction rows this call just inserted (and which existing
// rows it relabeled into a branch) — the only way to find those rows again
// once the /rubix/v1/signature response/request arrives as a separate HTTP
// call, since intent_id is now the nftId and is no longer unique per txn.
func (d *DB) InsertPendingBranch(reqID, intentID string, insertedIDs []string, renamed []RenamedInteractionID) error {
	payload, err := json.Marshal(pendingBranchPayload{InsertedIDs: insertedIDs, Renamed: renamed})
	if err != nil {
		return err
	}
	_, err = d.conn.Exec(
		`INSERT INTO pending_branches (req_id, intent_id, payload) VALUES ($1, $2, $3)
		 ON CONFLICT (req_id) DO UPDATE SET intent_id = $2, payload = $3, created_at = NOW()`,
		reqID, intentID, string(payload),
	)
	return err
}

// DeletePendingBranch removes the tracking row once /rubix/v1/signature
// confirms the txn succeeded — nothing else needs to change, since intent_id
// was already correct from insert time.
func (d *DB) DeletePendingBranch(reqID string) error {
	_, err := d.conn.Exec(`DELETE FROM pending_branches WHERE req_id = $1`, reqID)
	return err
}

// collectToolAgentPairsByIDs is collectToolAgentPairs restricted to an
// explicit list of interaction_ids rather than a single WHERE column match —
// used when rolling back a specific branch's rows (identified by id list),
// not a whole intent/provenance group.
func collectToolAgentPairsByIDs(tx *sql.Tx, ids []string) ([]toolAgentPair, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(`
		SELECT DISTINCT ni.initiator_did, ni.interacted_to_did
		FROM new_interactions ni
		JOIN new_tools t ON t.did = ni.interacted_to_did
		WHERE ni.interaction_id = ANY($1)`,
		pq.Array(ids),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pairs []toolAgentPair
	for rows.Next() {
		var p toolAgentPair
		if err := rows.Scan(&p.agentDID, &p.toolDID); err != nil {
			return nil, err
		}
		pairs = append(pairs, p)
	}
	return pairs, rows.Err()
}

// RollbackBranch undoes exactly one txn's contribution to an intent: deletes
// the rows it inserted, reverses any trunk-row relabeling that only happened
// because this (now-failing) branch revealed a fork, and — if the intent has
// no rows left at all afterward — deletes the intent row too. Otherwise the
// intent's interaction_ids list is recomputed from what's actually left, so a
// failed later branch never leaves stale references behind.
//
// Used both when /rubix/v1/tx itself reports status=false (called directly,
// synchronously, with the ids/renames handleIntentWorkflow just produced) and
// when /rubix/v1/signature fails (called via RollbackPendingBranch, which
// looks the same ids/renames up from the pending_branches row).
func (d *DB) RollbackBranch(intentID string, insertedIDs []string, renamed []RenamedInteractionID) (int64, int64, error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() // no-op after a successful Commit

	pairs, err := collectToolAgentPairsByIDs(tx, insertedIDs)
	if err != nil {
		return 0, 0, err
	}

	var interactionsDeleted int64
	if len(insertedIDs) > 0 {
		res, err := tx.Exec(`DELETE FROM new_interactions WHERE interaction_id = ANY($1)`, pq.Array(insertedIDs))
		if err != nil {
			return 0, 0, err
		}
		interactionsDeleted, _ = res.RowsAffected()
	}

	for _, r := range renamed {
		if _, err := tx.Exec(`UPDATE new_interactions SET interaction_id = $1 WHERE interaction_id = $2`, r.From, r.To); err != nil {
			return 0, 0, err
		}
	}

	var remaining int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM new_interactions WHERE intent_id = $1`, intentID).Scan(&remaining); err != nil {
		return 0, 0, err
	}

	var intentsDeleted int64
	if remaining == 0 {
		res2, err := tx.Exec(`DELETE FROM new_intents WHERE intent_id = $1`, intentID)
		if err != nil {
			return 0, 0, err
		}
		intentsDeleted, _ = res2.RowsAffected()
	} else {
		rows, err := tx.Query(`SELECT interaction_id FROM new_interactions WHERE intent_id = $1`, intentID)
		if err != nil {
			return 0, 0, err
		}
		var remainingIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, 0, err
			}
			remainingIDs = append(remainingIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, 0, err
		}
		remainingIDsJSON, err := json.Marshal(remainingIDs)
		if err != nil {
			return 0, 0, err
		}
		if _, err := tx.Exec(`UPDATE new_intents SET interaction_ids = $2 WHERE intent_id = $1`, intentID, string(remainingIDsJSON)); err != nil {
			return 0, 0, err
		}
	}

	if err := pruneToolAgentsList(tx, pairs); err != nil {
		return 0, 0, err
	}

	return interactionsDeleted, intentsDeleted, tx.Commit()
}

// RollbackPendingBranch is RollbackBranch for the /rubix/v1/signature failure
// path: it looks up which rows belong to reqID (since that call is a separate
// HTTP request from the /tx call that inserted them), rolls them back, and
// removes the tracking row. found=false means nothing was ever tagged with
// this reqID (e.g. InsertPendingBranch never ran).
func (d *DB) RollbackPendingBranch(reqID string) (interactionsDeleted, intentsDeleted int64, found bool, err error) {
	var intentID, payloadJSON string
	err = d.conn.QueryRow(`SELECT intent_id, payload FROM pending_branches WHERE req_id = $1`, reqID).Scan(&intentID, &payloadJSON)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	var payload pendingBranchPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return 0, 0, false, err
	}
	interactionsDeleted, intentsDeleted, err = d.RollbackBranch(intentID, payload.InsertedIDs, payload.Renamed)
	if err != nil {
		return 0, 0, false, err
	}
	if err := d.DeletePendingBranch(reqID); err != nil {
		return 0, 0, false, err
	}
	return interactionsDeleted, intentsDeleted, true, nil
}

// toolAgentPair is one (agent, tool) combination touched by interactions
// that are about to be deleted — captured before the delete so
// pruneToolAgentsList can tell afterward whether the pair has any
// interaction left at all.
type toolAgentPair struct {
	agentDID, toolDID string
}

// pruneToolAgentsList drops each pair's agentDID from its tool's agents_list
// once that agent has no interaction with the tool left at all — agents_list
// (populated by AddAgentToToolList as interactions happen) otherwise only
// ever grows, so an agent whose sole interaction with a tool gets deleted
// (a failed /tx rolled back) would stay listed as having contacted it
// forever.
func pruneToolAgentsList(tx *sql.Tx, pairs []toolAgentPair) error {
	for _, p := range pairs {
		var remaining int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM new_interactions WHERE initiator_did = $1 AND interacted_to_did = $2`,
			p.agentDID, p.toolDID,
		).Scan(&remaining); err != nil {
			return err
		}
		if remaining > 0 {
			continue
		}
		if _, err := tx.Exec(`
			UPDATE new_tools
			SET agents_list = (
				SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)::text
				FROM jsonb_array_elements_text(COALESCE(NULLIF(agents_list,'')::jsonb, '[]'::jsonb)) AS elem
				WHERE elem <> $2
			)
			WHERE did = $1`,
			p.toolDID, p.agentDID,
		); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) CountInteractionsByAgent(agentDID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE initiator_did = $1`, agentDID,
	).Scan(&total)
	return total, err
}

func scanInteractionNewRows(rows *sql.Rows) ([]*InteractionRecord, error) {
	var result []*InteractionRecord
	for rows.Next() {
		r := &InteractionRecord{}
		var threatInt int
		if err := rows.Scan(
			&r.InteractionID,
			&r.From, &r.FromName,
			&r.To, &r.ToName,
			&r.Type, &r.Direction, &threatInt, &r.IntentID, &r.Time, &r.Message,
			&r.Signature, &r.ThreatID,
		); err != nil {
			return nil, err
		}
		r.Threat = threatInt == 1
		result = append(result, r)
	}
	return result, nil
}

// scanInteractionNewRowsWithTitle is scanInteractionNewRows plus a trailing
// joined threat_codes.title column, for callers that list threats.
func scanInteractionNewRowsWithTitle(rows *sql.Rows) ([]*InteractionRecord, error) {
	var result []*InteractionRecord
	for rows.Next() {
		r := &InteractionRecord{}
		var threatInt int
		if err := rows.Scan(
			&r.InteractionID,
			&r.From, &r.FromName,
			&r.To, &r.ToName,
			&r.Type, &r.Direction, &threatInt, &r.IntentID, &r.Time, &r.Message,
			&r.Signature, &r.ThreatID,
			&r.ThreatCode, &r.ThreatTitle, &r.ReviewStatus,
		); err != nil {
			return nil, err
		}
		r.Threat = threatInt == 1
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetInteractionsByAgent(agentDID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions
		WHERE initiator_did = $1
		ORDER BY time DESC
		LIMIT $2 OFFSET $3`,
		agentDID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func (d *DB) CountIntentsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_intents WHERE organization_id = $1`, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetIntentsByOrg(orgID string, limit, offset int) ([]*IntentRecord, error) {
	rows, err := d.conn.Query(`
		SELECT ni.intent_id, ni.initiator_did,
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, COALESCE(ni.review_status, 'Unreviewed'), ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(i.interaction_id)                                                AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN i.interacted_to_did END) AS tools_count,
		       SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                          AS threat_count,
		       MIN(i.time)                                                             AS first_interaction_at,
		       MAX(i.time)                                                             AS last_interaction_at,
		       COALESCE((SELECT message FROM new_interactions
		        WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), '') AS title
		FROM new_intents ni
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		LEFT JOIN new_interactions i ON i.intent_id = ni.intent_id
		LEFT JOIN new_agents a ON a.did = i.interacted_to_did
		LEFT JOIN new_tools t ON t.did = i.interacted_to_did
		WHERE ni.organization_id = $1
		GROUP BY ni.intent_id, u.name, ag_init.name
		ORDER BY ni.started_at DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*IntentRecord
	for rows.Next() {
		r := &IntentRecord{}
		var endedAt, firstAt, lastAt sql.NullTime
		var threatInt int
		if err := rows.Scan(
			&r.IntentID, &r.InitiatorDID, &r.InitiatorName, &r.OrgID,
			&r.StartedAt, &endedAt, &r.Status, &r.ReviewStatus, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth,
			&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount, &r.ThreatCount,
			&firstAt, &lastAt, &r.Title,
		); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		if endedAt.Valid {
			r.EndedAt = &endedAt.Time
		}
		if firstAt.Valid {
			r.FirstInteractionAt = &firstAt.Time
		}
		if lastAt.Valid {
			r.LastInteractionAt = &lastAt.Time
			if firstAt.Valid {
				r.RuntimeSeconds = lastAt.Time.Sub(firstAt.Time).Seconds()
			}
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) CountAgentIntents(agentDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT ni.intent_id)
		FROM new_intents ni
		JOIN new_interactions i ON i.intent_id = ni.intent_id
		WHERE i.initiator_did = $1 AND ni.organization_id = $2`,
		agentDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetAgentIntents(agentDID, orgID string, limit, offset int) ([]*IntentRecord, error) {
	rows, err := d.conn.Query(`
		SELECT ni.intent_id, ni.initiator_did, COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''), ni.started_at,
		       ni.ended_at, ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COALESCE((SELECT message FROM new_interactions
		        WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), '') AS title
		FROM new_intents ni
		JOIN new_interactions i ON i.intent_id = ni.intent_id
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		WHERE i.initiator_did = $1 AND ni.organization_id = $2
		GROUP BY ni.intent_id, u.name, ag_init.name
		ORDER BY ni.started_at DESC
		LIMIT $3 OFFSET $4`,
		agentDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIntentRows(rows)
}

func (d *DB) CountUserIntents(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM new_intents WHERE initiator_did = $1 AND organization_id = $2`,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetUserIntents(userDID, orgID string, limit, offset int) ([]*IntentRecord, error) {
	rows, err := d.conn.Query(`
		SELECT ni.intent_id, ni.initiator_did, COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''), ni.started_at, ni.ended_at,
		       ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COALESCE((SELECT message FROM new_interactions
		        WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), '') AS title
		FROM new_intents ni
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		WHERE ni.initiator_did = $1 AND ni.organization_id = $2
		ORDER BY ni.started_at DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIntentRows(rows)
}

func scanIntentRows(rows *sql.Rows) ([]*IntentRecord, error) {
	var result []*IntentRecord
	for rows.Next() {
		r := &IntentRecord{}
		var endedAt sql.NullTime
		var threatInt int
		if err := rows.Scan(
			&r.IntentID, &r.InitiatorDID, &r.InitiatorName, &r.StartedAt, &endedAt,
			&r.Status, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth, &r.Title,
		); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		if endedAt.Valid {
			r.EndedAt = &endedAt.Time
		}
		result = append(result, r)
	}
	return result, nil
}

// GetAgentInteractedApps returns the distinct tools (from the new_tools table) that the
// agent has interacted with — either as initiator or recipient in new_interactions.
func (d *DB) GetAgentInteractedApps(agentDID string) ([]string, error) {
	rows, err := d.conn.Query(`
		SELECT DISTINCT a.name
		FROM new_tools a
		WHERE a.did IN (
			SELECT interacted_to_did FROM new_interactions WHERE initiator_did = $1
			UNION
			SELECT initiator_did FROM new_interactions WHERE interacted_to_did = $1
		)
		ORDER BY a.name ASC`,
		agentDID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func (d *DB) GetAgentInfo(agentDID string) (*AgentDetailRecord, error) {
	r := &AgentDetailRecord{}
	err := d.conn.QueryRow(`
		SELECT
			a.did,
			COALESCE(NULLIF(a.name, ''), ''),
			COALESCE(a.created_at, NOW()),
			COALESCE(a.deployer_did, ''),
			COALESCE(a.policy, ''),
			COUNT(i.interaction_id)                                              AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                       AS total_threats,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                  AS score,
			a.revoked
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.did = $1
		GROUP BY a.did, a.name, a.created_at, a.deployer_did, a.policy, a.revoked`,
		agentDID,
	).Scan(&r.AgentDID, &r.AgentName, &r.CreatedAt, &r.DeployerDID, &r.Policy,
		&r.TotalInteractions, &r.TotalThreats, &r.Score, &r.Revoked)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (d *DB) GetIntentInfo(intentID string) (*IntentRecord, error) {
	r := &IntentRecord{}
	var endedAt, firstAt, lastAt sql.NullTime
	var orgID sql.NullString
	var threatInt int
	err := d.conn.QueryRow(`
		SELECT ni.intent_id, ni.initiator_did,
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, COALESCE(ni.review_status, 'Unreviewed'), ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(i.interaction_id)                                                AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN i.interacted_to_did END) AS tools_count,
		       MIN(i.time)                                                             AS first_interaction_at,
		       MAX(i.time)                                                             AS last_interaction_at
		FROM new_intents ni
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		LEFT JOIN new_interactions i ON i.intent_id = ni.intent_id
		LEFT JOIN new_agents a ON a.did = i.interacted_to_did
		LEFT JOIN new_tools t ON t.did = i.interacted_to_did
		WHERE ni.intent_id = $1
		GROUP BY ni.intent_id, u.name, ag_init.name`, intentID,
	).Scan(
		&r.IntentID, &r.InitiatorDID, &r.InitiatorName, &orgID,
		&r.StartedAt, &endedAt, &r.Status, &r.ReviewStatus, &threatInt,
		&r.FlowType, &r.Executor, &r.ChainDepth,
		&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount,
		&firstAt, &lastAt,
	)
	if err != nil {
		return nil, err
	}
	r.OrgID = orgID.String
	r.ThreatDetected = threatInt == 1
	if endedAt.Valid {
		r.EndedAt = &endedAt.Time
	}
	if firstAt.Valid {
		r.FirstInteractionAt = &firstAt.Time
	}
	if lastAt.Valid {
		r.LastInteractionAt = &lastAt.Time
		if firstAt.Valid {
			r.RuntimeSeconds = lastAt.Time.Sub(firstAt.Time).Seconds()
		}
	}
	return r, nil
}

// CountUnacknowledgedThreatIntentsByOrg counts the org's threat intents
// (threat_detected = 1) whose review_status is anything other than
// Acknowledged. Clean intents never count, whatever their review_status.
func (d *DB) CountUnacknowledgedThreatIntentsByOrg(orgID string) (int, error) {
	var n int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM new_intents
		WHERE organization_id = $1
		  AND threat_detected = 1
		  AND COALESCE(review_status, 'Unreviewed') <> 'Acknowledged'`,
		orgID,
	).Scan(&n)
	return n, err
}

// CountUnacknowledgedThreatIntentsByUser is the user-scoped variant of
// CountUnacknowledgedThreatIntentsByOrg, limited to the intents the user can see.
func (d *DB) CountUnacknowledgedThreatIntentsByUser(userDID, orgID string) (int, error) {
	var n int
	err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(*) FROM new_intents ni
		WHERE ni.intent_id IN (SELECT intent_id FROM user_intents)
		  AND ni.threat_detected = 1
		  AND COALESCE(ni.review_status, 'Unreviewed') <> 'Acknowledged'`,
		userDID, orgID,
	).Scan(&n)
	return n, err
}

// UpdateIntentReviewStatus sets the human-triage review_status (Unreviewed /
// Acknowledged / Flagged) for an intent, scoped to the caller's org so one
// org can't touch another's intents. Returns sql.ErrNoRows if no row matched
// (bad intentID or org mismatch).
func (d *DB) UpdateIntentReviewStatus(intentID, orgID, status string) error {
	res, err := d.conn.Exec(
		`UPDATE new_intents SET review_status = $1 WHERE intent_id = $2 AND organization_id = $3`,
		status, intentID, orgID,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) GetInteractionsByIntent(intentID string) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions WHERE intent_id = $1 ORDER BY time ASC`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

// GetInteractionRawDataByIntent returns each interaction's stored raw
// envelope JSON for the given intent, keyed by interaction_id. Kept separate
// from GetInteractionsByIntent so scanInteractionNewRows (shared by every
// interaction list query) doesn't drag the raw payload along everywhere.
func (d *DB) GetInteractionRawDataByIntent(intentID string) (map[string]json.RawMessage, error) {
	rows, err := d.conn.Query(
		`SELECT interaction_id, COALESCE(raw_data, '{}') FROM new_interactions WHERE intent_id = $1`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]json.RawMessage{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		result[id] = json.RawMessage(raw)
	}
	return result, rows.Err()
}

func (d *DB) GetToolByNameOrDID(query, orgID string) (*ToolRecord, error) {
	r := &ToolRecord{}
	var lastAt sql.NullTime
	err := d.conn.QueryRow(`
		SELECT
			t.did,
			t.name,
			COUNT(i.interaction_id)                                                     AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                              AS total_threats,
			COUNT(DISTINCT i.intent_id)                                                 AS total_intents,
			COUNT(DISTINCT a.did)                                                       AS total_agents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END AS score,
			MAX(i.time) AS last_interacted_at
		FROM new_tools t
		-- Count the tool's traffic whichever side of the interaction it's on
		-- (interacted_to_did for tool-called-by-agent, initiator_did for the
		-- rarer tool-initiates-a-response direction).
		LEFT JOIN new_interactions i
		       ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		      AND i.organization_id = $1
		-- The "other party" on that interaction — whichever side isn't this tool.
		LEFT JOIN new_agents a
		       ON a.did = CASE WHEN i.interacted_to_did = t.did THEN i.initiator_did ELSE i.interacted_to_did END
		WHERE t.organization_id = $1
		  AND (t.did = $2 OR t.name = $2)
		GROUP BY t.did, t.name
		LIMIT 1`,
		orgID, query,
	).Scan(&r.DID, &r.Name, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents, &r.TotalAgents, &r.Score, &lastAt)
	if err != nil {
		return nil, err
	}
	if lastAt.Valid {
		r.LastInteractedAt = &lastAt.Time
	}
	return r, nil
}

func (d *DB) CountIntentsByTool(toolDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT ni.intent_id)
		FROM new_intents ni
		JOIN new_interactions i ON i.intent_id = ni.intent_id
		WHERE i.interacted_to_did = $1 AND ni.organization_id = $2`,
		toolDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetIntentsByTool(toolDID, orgID string, limit, offset int) ([]*IntentRecord, error) {
	rows, err := d.conn.Query(`
		SELECT ni.intent_id, ni.initiator_did,
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), NULLIF(ni.initiator_name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(ix.interaction_id)                                                 AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN ix.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN ix.interacted_to_did END) AS tools_count,
		       SUM(CASE WHEN ix.threat = 1 THEN 1 ELSE 0 END)                           AS threat_count,
		       MIN(ix.time)                                                              AS first_interaction_at,
		       MAX(ix.time)                                                              AS last_interaction_at,
		       COALESCE((SELECT message FROM new_interactions
		        WHERE intent_id = ni.intent_id ORDER BY time ASC LIMIT 1), '') AS title
		FROM new_intents ni
		JOIN new_interactions tool_ix ON tool_ix.intent_id = ni.intent_id AND tool_ix.interacted_to_did = $1
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		LEFT JOIN new_agents ag_init ON ag_init.did = ni.initiator_did
		LEFT JOIN new_interactions ix ON ix.intent_id = ni.intent_id
		LEFT JOIN new_agents a ON a.did = ix.interacted_to_did
		LEFT JOIN new_tools t ON t.did = ix.interacted_to_did
		WHERE ni.organization_id = $2
		GROUP BY ni.intent_id, u.name, ag_init.name
		ORDER BY ni.started_at DESC
		LIMIT $3 OFFSET $4`,
		toolDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*IntentRecord
	for rows.Next() {
		r := &IntentRecord{}
		var endedAt, firstAt, lastAt sql.NullTime
		var threatInt int
		if err := rows.Scan(
			&r.IntentID, &r.InitiatorDID, &r.InitiatorName, &r.OrgID,
			&r.StartedAt, &endedAt, &r.Status, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth,
			&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount, &r.ThreatCount,
			&firstAt, &lastAt, &r.Title,
		); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		if endedAt.Valid {
			r.EndedAt = &endedAt.Time
		}
		if firstAt.Valid {
			r.FirstInteractionAt = &firstAt.Time
		}
		if lastAt.Valid {
			r.LastInteractionAt = &lastAt.Time
			if firstAt.Valid {
				r.RuntimeSeconds = lastAt.Time.Sub(firstAt.Time).Seconds()
			}
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) StoreNewTool(did, name, orgID string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_tools (did, name, organization_id) VALUES ($1, $2, $3) ON CONFLICT (did) DO NOTHING`,
		did, name, orgID,
	)
	return err
}

// AddAgentToToolList records that agentDID has contacted tool toolDID, adding
// it to the tool's agents_list if not already present. Done as a single
// atomic UPDATE (cast the TEXT column to jsonb, append, de-dupe, cast back)
// rather than read-modify-write in Go, since multiple intents touching the
// same tool concurrently would otherwise race and drop updates.
func (d *DB) AddAgentToToolList(toolDID, agentDID string) error {
	_, err := d.conn.Exec(`
		UPDATE new_tools
		SET agents_list = (
			SELECT COALESCE(jsonb_agg(DISTINCT elem), '[]'::jsonb)::text
			FROM jsonb_array_elements_text(
				COALESCE(NULLIF(agents_list, '')::jsonb, '[]'::jsonb) || to_jsonb($2::text)
			) AS elem
		)
		WHERE did = $1`,
		toolDID, agentDID,
	)
	return err
}

// GetToolAgentsList returns the tool's name and its de-duplicated list of
// contacted agent DIDs (agents_list), scoped to orgID.
func (d *DB) GetToolAgentsList(toolDID, orgID string) (name string, agents []string, err error) {
	var agentsJSON string
	err = d.conn.QueryRow(
		`SELECT name, COALESCE(agents_list, '[]') FROM new_tools WHERE did = $1 AND organization_id = $2`,
		toolDID, orgID,
	).Scan(&name, &agentsJSON)
	if err != nil {
		return "", nil, err
	}
	_ = json.Unmarshal([]byte(agentsJSON), &agents)
	return name, agents, nil
}

func (d *DB) CountToolsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT t.did) FROM new_tools t
		INNER JOIN new_interactions i
		        ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		       AND i.organization_id = $1`,
		orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetToolsByOrg(orgID string, limit, offset int) ([]*ToolRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			t.did,
			t.name,
			COUNT(i.interaction_id)                                                     AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                              AS total_threats,
			COUNT(DISTINCT i.intent_id)                                                 AS total_intents,
			COUNT(DISTINCT a.did)                                                       AS total_agents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                         AS score
		FROM new_tools t
		INNER JOIN new_interactions i
		        ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		       AND i.organization_id = $1
		LEFT JOIN new_agents a
		       ON a.did = CASE WHEN i.interacted_to_did = t.did THEN i.initiator_did ELSE i.interacted_to_did END
		GROUP BY t.did, t.name
		ORDER BY total_interactions DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanToolRows(rows)
}

func (d *DB) GetToolInfo(toolDID, orgID string) (*ToolRecord, error) {
	r := &ToolRecord{}
	err := d.conn.QueryRow(`
		SELECT
			t.did,
			t.name,
			COUNT(i.interaction_id)                                                     AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                              AS total_threats,
			COUNT(DISTINCT i.intent_id)                                                 AS total_intents,
			COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.initiator_did END)        AS total_agents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                         AS score
		FROM new_tools t
		LEFT JOIN new_interactions i ON i.interacted_to_did = t.did AND i.organization_id = $1
		LEFT JOIN new_agents a ON a.did = i.initiator_did
		WHERE t.did = $2
		GROUP BY t.did, t.name`,
		orgID, toolDID,
	).Scan(&r.DID, &r.Name, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents, &r.TotalAgents, &r.Score)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (d *DB) CountInteractionsByTool(toolDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM new_interactions WHERE interacted_to_did = $1 AND organization_id = $2`,
		toolDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetInteractionsByTool(toolDID, orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, ''),
		       COALESCE(signature, ''), COALESCE(threat_id, '')
		FROM new_interactions
		WHERE interacted_to_did = $1 AND organization_id = $2
		ORDER BY time DESC
		LIMIT $3 OFFSET $4`,
		toolDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func scanToolRows(rows *sql.Rows) ([]*ToolRecord, error) {
	var result []*ToolRecord
	for rows.Next() {
		r := &ToolRecord{}
		if err := rows.Scan(&r.DID, &r.Name, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents, &r.TotalAgents, &r.Score); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) UpdateUserPassword(email, passwordHash string) error {
	res, err := d.conn.Exec(
		`UPDATE new_org_users SET password = $1 WHERE email = $2`, passwordHash, email,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no user found with email %s", email)
	}
	return nil
}

func (d *DB) UpdateAdminName(email, name string) error {
	res, err := d.conn.Exec(`UPDATE new_admins SET name = $1 WHERE email = $2`, name, email)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) UpdateAdminEmail(currentEmail, newEmail string) error {
	var exists bool
	d.conn.QueryRow(`SELECT EXISTS(SELECT 1 FROM new_admins WHERE email = $1)`, newEmail).Scan(&exists)
	if exists {
		return fmt.Errorf("email already in use")
	}
	res, err := d.conn.Exec(`UPDATE new_admins SET email = $1 WHERE email = $2`, newEmail, currentEmail)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) UpdateAdminPassword(email, passwordHash string) error {
	res, err := d.conn.Exec(
		`UPDATE new_admins SET password = $1 WHERE email = $2`, passwordHash, email,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no admin found with email %s", email)
	}
	return nil
}

// InteractionSeriesBucket holds safe and threat counts for one time bucket.
type InteractionSeriesBucket struct {
	Safe    int
	Threats int
}

// GetInteractionSeries returns bucketed interaction counts for an org.
// For range "24h": 24 hourly buckets, index 0 = 23 hours ago, index 23 = current hour.
// For range "7d":  7 daily buckets,  index 0 = 6 days ago,    index 6 = today.
func (d *DB) GetInteractionSeries(orgID, rangeParam string) ([]InteractionSeriesBucket, error) {
	now := time.Now().UTC()

	var buckets []InteractionSeriesBucket
	var query string
	var args []any

	if rangeParam == "7d" {
		buckets = make([]InteractionSeriesBucket, 7)
		// bucket index = days ago from today (0 = oldest = 6 days ago, 6 = today)
		query = `
			SELECT
				CAST(FLOOR(EXTRACT(EPOCH FROM ($1::timestamptz - time)) / 86400) AS INT) AS bucket,
				SUM(CASE WHEN threat = 0 THEN 1 ELSE 0 END),
				SUM(CASE WHEN threat = 1 THEN 1 ELSE 0 END)
			FROM new_interactions
			WHERE organization_id = $2
			  AND time >= $1::timestamptz - INTERVAL '7 days'
			  AND time <  $1::timestamptz + INTERVAL '1 day'
			GROUP BY bucket`
		args = []any{now, orgID}
	} else {
		// default: 24h
		buckets = make([]InteractionSeriesBucket, 24)
		query = `
			SELECT
				CAST(FLOOR(EXTRACT(EPOCH FROM ($1::timestamptz - time)) / 3600) AS INT) AS bucket,
				SUM(CASE WHEN threat = 0 THEN 1 ELSE 0 END),
				SUM(CASE WHEN threat = 1 THEN 1 ELSE 0 END)
			FROM new_interactions
			WHERE organization_id = $2
			  AND time >= $1::timestamptz - INTERVAL '24 hours'
			GROUP BY bucket`
		args = []any{now, orgID}
	}

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	size := len(buckets)
	for rows.Next() {
		var daysOrHoursAgo, safe, threats int
		if err := rows.Scan(&daysOrHoursAgo, &safe, &threats); err != nil {
			continue
		}
		// daysOrHoursAgo=0 means current bucket → last index; invert to get ascending order
		idx := size - 1 - daysOrHoursAgo
		if idx >= 0 && idx < size {
			buckets[idx].Safe = safe
			buckets[idx].Threats = threats
		}
	}
	return buckets, rows.Err()
}

type AgentsAppsMetrics struct {
	TopAgents         []*AgentVolumeRecord
	TopApps           []*ToolRecord
	TotalInteractions int
	TotalThreats      int
	TotalAgents       int
	TotalApps         int
	AvgReliability    float64
}

func (d *DB) GetAgentsAppsMetrics(orgID string) (*AgentsAppsMetrics, error) {
	out := &AgentsAppsMetrics{}

	// Top 5 agents by interaction volume.
	agentRows, err := d.GetTopAgentsByOrg(orgID, 5, 0)
	if err != nil {
		return nil, err
	}
	out.TopAgents = agentRows

	// Top 5 apps by interaction volume.
	appRows, err := d.GetToolsByOrg(orgID, 5, 0)
	if err != nil {
		return nil, err
	}
	out.TopApps = appRows

	// Aggregate counts.
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1`, orgID,
	).Scan(&out.TotalInteractions); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND threat = 1`, orgID,
	).Scan(&out.TotalThreats); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_agents WHERE organization_id = $1`, orgID,
	).Scan(&out.TotalAgents); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(
		`SELECT COUNT(DISTINCT t.did) FROM new_tools t
		 INNER JOIN new_interactions i
		         ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		        AND i.organization_id = $1`,
		orgID,
	).Scan(&out.TotalApps); err != nil {
		return nil, err
	}

	// Average reliability across all agents: AVG(1 - threats/interactions) * 100.
	// Agents with zero interactions are treated as 100% reliable.
	if err := d.conn.QueryRow(`
		SELECT COALESCE(AVG(
			CASE
				WHEN total_interactions = 0 THEN 100.0
				ELSE ROUND(CAST((1.0 - total_threats * 1.0 / total_interactions) * 100 AS NUMERIC), 2)
			END
		), 100.0)
		FROM (
			SELECT
				COUNT(i.interaction_id)                        AS total_interactions,
				SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) AS total_threats
			FROM new_agents a
			LEFT JOIN new_interactions i
			       ON i.initiator_did = a.did AND i.organization_id = $1
			WHERE a.organization_id = $1
			GROUP BY a.did
		) agent_stats`,
		orgID,
	).Scan(&out.AvgReliability); err != nil {
		return nil, err
	}

	return out, nil
}

// GetAgentsAppsMetricsByUser is the non-admin counterpart of GetAgentsAppsMetrics
// — every count is scoped to interactions the user (or one of the agents they
// deployed / were granted access to, via user_agents) actually took part in,
// instead of the whole org's totals.
func (d *DB) GetAgentsAppsMetricsByUser(userDID, orgID string) (*AgentsAppsMetrics, error) {
	out := &AgentsAppsMetrics{}

	// Top 5 of the user's own agents by interaction volume.
	agentRows, err := d.GetTopAgentsByUser(userDID, orgID, 5, 0)
	if err != nil {
		return nil, err
	}
	out.TopAgents = agentRows

	// Top 5 apps the user (or their agents) actually interacted with.
	appRows, err := d.getToolsByUser(userDID, orgID, 5, 0)
	if err != nil {
		return nil, err
	}
	out.TopApps = appRows

	if err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(*) FROM new_interactions i
		WHERE i.organization_id = $2
		  AND (
		      i.initiator_did = $1
		      OR i.initiator_did IN (SELECT did FROM user_agents)
		      OR i.interacted_to_did IN (SELECT did FROM user_agents)
		  )`,
		userDID, orgID,
	).Scan(&out.TotalInteractions); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(*) FROM new_interactions i
		WHERE i.organization_id = $2 AND i.threat = 1
		  AND (
		      i.initiator_did = $1
		      OR i.initiator_did IN (SELECT did FROM user_agents)
		      OR i.interacted_to_did IN (SELECT did FROM user_agents)
		  )`,
		userDID, orgID,
	).Scan(&out.TotalThreats); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(
		`SELECT COUNT(*) FROM new_agents WHERE deployer_did = $1`, userDID,
	).Scan(&out.TotalAgents); err != nil {
		return nil, err
	}
	if err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT COUNT(DISTINCT t.did) FROM new_tools t
		INNER JOIN new_interactions i
		        ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		       AND i.organization_id = $2
		WHERE (
		    i.initiator_did = $1
		    OR i.initiator_did IN (SELECT did FROM user_agents)
		    OR i.interacted_to_did IN (SELECT did FROM user_agents)
		)`,
		userDID, orgID,
	).Scan(&out.TotalApps); err != nil {
		return nil, err
	}

	// Average reliability across just the user's own agents.
	if err := d.conn.QueryRow(`
		SELECT COALESCE(AVG(
			CASE
				WHEN total_interactions = 0 THEN 100.0
				ELSE ROUND(CAST((1.0 - total_threats * 1.0 / total_interactions) * 100 AS NUMERIC), 2)
			END
		), 100.0)
		FROM (
			SELECT
				COUNT(i.interaction_id)                        AS total_interactions,
				SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) AS total_threats
			FROM new_agents a
			LEFT JOIN new_interactions i
			       ON i.initiator_did = a.did AND i.organization_id = $2
			WHERE a.deployer_did = $1
			GROUP BY a.did
		) agent_stats`,
		userDID, orgID,
	).Scan(&out.AvgReliability); err != nil {
		return nil, err
	}

	return out, nil
}

// getToolsByUser scopes GetToolsByOrg down to just the apps the user (or one
// of their agents, via user_agents) actually interacted with. Expects
// userScopeIntentsCTE to already be prefixed onto the query by the caller.
func (d *DB) getToolsByUser(userDID, orgID string, limit, offset int) ([]*ToolRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT
			t.did,
			t.name,
			COUNT(i.interaction_id)                                                     AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                              AS total_threats,
			COUNT(DISTINCT i.intent_id)                                                 AS total_intents,
			COUNT(DISTINCT a.did)                                                       AS total_agents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                                                         AS score
		FROM new_tools t
		INNER JOIN new_interactions i
		        ON (i.interacted_to_did = t.did OR i.initiator_did = t.did)
		       AND i.organization_id = $2
		LEFT JOIN new_agents a
		       ON a.did = CASE WHEN i.interacted_to_did = t.did THEN i.initiator_did ELSE i.interacted_to_did END
		WHERE (
		    i.initiator_did = $1
		    OR i.initiator_did IN (SELECT did FROM user_agents)
		    OR i.interacted_to_did IN (SELECT did FROM user_agents)
		)
		GROUP BY t.did, t.name
		ORDER BY total_interactions DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanToolRows(rows)
}

func (d *DB) Search(q, orgID string) (*SearchResults, error) {
	out := &SearchResults{
		Agents:  []SearchAgentResult{},
		Apps:    []SearchAppResult{},
		Intents: []SearchIntentResult{},
	}
	pattern := "%" + q + "%"

	// Agents — match name or DID, scoped to org.
	agentRows, err := d.conn.Query(`
		SELECT did, COALESCE(name,''), organization_id
		FROM new_agents
		WHERE organization_id = $1
		  AND (name ILIKE $2 OR did ILIKE $2)
		ORDER BY name ASC
		LIMIT 20`,
		orgID, pattern,
	)
	if err != nil {
		return nil, err
	}
	defer agentRows.Close()
	for agentRows.Next() {
		var r SearchAgentResult
		if err := agentRows.Scan(&r.DID, &r.Name, &r.OrgID); err != nil {
			return nil, err
		}
		out.Agents = append(out.Agents, r)
	}

	// Apps/tools — match name, scoped to org.
	appRows, err := d.conn.Query(`
		SELECT did, COALESCE(name,'')
		FROM new_tools
		WHERE organization_id = $1
		  AND name ILIKE $2
		ORDER BY name ASC
		LIMIT 20`,
		orgID, pattern,
	)
	if err != nil {
		return nil, err
	}
	defer appRows.Close()
	for appRows.Next() {
		var r SearchAppResult
		if err := appRows.Scan(&r.DID, &r.Name); err != nil {
			return nil, err
		}
		out.Apps = append(out.Apps, r)
	}

	// Intents — exact match on intent_id, scoped to org.
	intentRows, err := d.conn.Query(`
		SELECT intent_id, COALESCE(flow_type,''), COALESCE(status,''), threat_detected, started_at
		FROM new_intents
		WHERE organization_id = $1
		  AND intent_id = $2
		LIMIT 5`,
		orgID, q,
	)
	if err != nil {
		return nil, err
	}
	defer intentRows.Close()
	for intentRows.Next() {
		var r SearchIntentResult
		var threatInt int
		if err := intentRows.Scan(&r.IntentID, &r.FlowType, &r.Status, &threatInt, &r.StartedAt); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		out.Intents = append(out.Intents, r)
	}

	return out, nil
}

// ownerAgentFilter is the SQL fragment that resolves which agents a user "owns".
// Bind: $1 = userDID, $2 = orgID.
const ownerAgentFilter = `
    a.organization_id = $2
    AND (
        a.deployer_did = $1
        OR a.did IN (
            SELECT agent_did FROM new_requests
            WHERE creator_did = $1 AND request_type = 'deploy_agent' AND status = 'approved'
        )
    )`

func (d *DB) GetUserDetail(userDID, orgID string) (*UserInfoRecord, error) {
	r := &UserInfoRecord{}
	var lastAt sql.NullTime
	err := d.conn.QueryRow(`
		SELECT
			COALESCE(u.did, ''),
			COALESCE(u.email, ''),
			COALESCE(u.name, ''),
			COALESCE(u.created_at, NOW()),
			(SELECT COUNT(*) FROM json_array_elements_text(COALESCE(u.agent_access_list,'[]')::json)) AS access_agent_count,
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND initiator_did = $1) AS total_interactions,
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND initiator_did = $1 AND threat = 1) AS total_threats,
			(SELECT COUNT(*) FROM new_intents WHERE organization_id = $2 AND initiator_did = $1) AS total_intents,
			(SELECT COUNT(DISTINCT a.did) FROM new_agents a
			 WHERE a.organization_id = $2
			   AND (a.deployer_did = $1
			        OR a.did IN (SELECT agent_did FROM new_requests
			                     WHERE creator_did = $1 AND request_type = 'deploy_agent' AND status = 'approved'))
			) AS total_agents_owned,
			(SELECT MAX(i.time) FROM new_interactions i WHERE i.organization_id = $2 AND i.initiator_did = $1) AS last_active
		FROM new_org_users u
		WHERE u.did = $1`,
		userDID, orgID,
	).Scan(
		&r.UserDID, &r.UserName, &r.DisplayName, &r.CreatedAt,
		&r.AccessAgentCount, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents,
		&r.TotalAgentsOwned, &lastAt,
	)
	if err != nil {
		return nil, err
	}
	if lastAt.Valid {
		r.LastActive = &lastAt.Time
		r.IsActive = true
	}
	return r, nil
}

func (d *DB) CountAgentsByOwner(userDID, orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT a.did) FROM new_agents a
		WHERE `+ownerAgentFilter,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetAgentsByOwner(userDID, orgID string, limit, offset int) ([]*UserAgentRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			a.did,
			COALESCE(NULLIF(a.name,''), ''),
			COALESCE(a.created_at, NOW()),
			COUNT(i.interaction_id) AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) AS total_threats,
			CASE WHEN COUNT(i.interaction_id) = 0 THEN 100.0
			     ELSE ROUND(CAST((1.0 - SUM(CASE WHEN i.threat=1 THEN 1 ELSE 0 END)*1.0
			          / COUNT(i.interaction_id))*100 AS NUMERIC), 2)
			END AS score
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE `+ownerAgentFilter+`
		GROUP BY a.did, a.name, a.created_at
		ORDER BY total_interactions DESC
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*UserAgentRecord
	for rows.Next() {
		r := &UserAgentRecord{}
		if err := rows.Scan(&r.AgentDID, &r.AgentName, &r.CreatedAt,
			&r.TotalInteractions, &r.TotalThreats, &r.Score); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetThreats(orgID string, limit, offset int) ([]*ThreatRecord, int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM threats t
		JOIN new_intents ni ON t.intent_id = ni.intent_id
		WHERE ni.organization_id = $1`, orgID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := d.conn.Query(`
		SELECT t.id, t.intent_id, t.interaction_id, t.time, t.threat_code, t.message
		FROM threats t
		JOIN new_intents ni ON t.intent_id = ni.intent_id
		WHERE ni.organization_id = $1
		ORDER BY t.time DESC
		LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var result []*ThreatRecord
	for rows.Next() {
		r := &ThreatRecord{}
		if err := rows.Scan(&r.ID, &r.IntentID, &r.InteractionID, &r.Time, &r.ThreatCode, &r.Message); err != nil {
			return nil, 0, err
		}
		result = append(result, r)
	}
	return result, total, nil
}

func (d *DB) GetTopThreats(orgID string) ([]*TopThreatRecord, error) {
	// Counted off new_interactions (one row per deduplicated interaction) rather
	// than raw COUNT(*) on threats — the threats table can carry duplicate rows
	// per interaction (see StoreThreat/idx-drift), which previously inflated
	// this total past what home-metrics/threats-list report.
	//
	// Every threat_code with a nonzero count is returned (no LIMIT) — the JOINs
	// already drop any code with zero occurrences, so there's nothing to filter
	// after the fact. threats is LEFT JOINed (not INNER) so a threat-flagged
	// interaction with no matching/resolved threat_code (missing threat_id, or
	// a threats row whose threat_code was never set) still gets counted, bucketed
	// under code 0 — the handler renders that bucket as "0000".
	rows, err := d.conn.Query(`
		SELECT COALESCE(t.threat_code, 0), COALESCE(tc.title, ''), COUNT(*) AS cnt
		FROM new_interactions ni
		LEFT JOIN threats t ON t.id = ni.threat_id
		LEFT JOIN threat_codes tc ON tc.code = t.threat_code
		WHERE ni.threat = 1
		GROUP BY COALESCE(t.threat_code, 0), COALESCE(tc.title, '')
		ORDER BY cnt DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*TopThreatRecord
	for rows.Next() {
		r := &TopThreatRecord{}
		if err := rows.Scan(&r.ThreatCode, &r.Title, &r.Count); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// GetTopThreatsByUser is the non-admin counterpart of GetTopThreats — scoped
// to threats on interactions belonging to one of the user's own intents
// (intent_id IN user_intents), the same scoping GetUserMetrics already uses
// for its interaction/threat counts, rather than every threat in the org.
func (d *DB) GetTopThreatsByUser(userDID, orgID string) ([]*TopThreatRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT COALESCE(t.threat_code, 0), COALESCE(tc.title, ''), COUNT(*) AS cnt
		FROM new_interactions ni
		LEFT JOIN threats t ON t.id = ni.threat_id
		LEFT JOIN threat_codes tc ON tc.code = t.threat_code
		WHERE ni.threat = 1 AND ni.intent_id IN (SELECT intent_id FROM user_intents)
		GROUP BY COALESCE(t.threat_code, 0), COALESCE(tc.title, '')
		ORDER BY cnt DESC`,
		userDID, orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*TopThreatRecord
	for rows.Next() {
		r := &TopThreatRecord{}
		if err := rows.Scan(&r.ThreatCode, &r.Title, &r.Count); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) GetThreatCodeDetail(code int) (*ThreatCodeRecord, error) {
	r := &ThreatCodeRecord{}
	err := d.conn.QueryRow(`
		SELECT code, title, description FROM threat_codes WHERE code = $1`, code).
		Scan(&r.Code, &r.Title, &r.Description)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (d *DB) GetThreatsByCode(orgID string, code int) ([]*ThreatRecord, int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(*) FROM threats t
		JOIN new_intents ni ON t.intent_id = ni.intent_id
		WHERE ni.organization_id = $1 AND t.threat_code = $2`, orgID, code).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := d.conn.Query(`
		SELECT t.id, t.intent_id, t.interaction_id, t.time, t.threat_code, t.message
		FROM threats t
		JOIN new_intents ni ON t.intent_id = ni.intent_id
		WHERE ni.organization_id = $1 AND t.threat_code = $2
		ORDER BY t.time DESC`,
		orgID, code,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var result []*ThreatRecord
	for rows.Next() {
		r := &ThreatRecord{}
		if err := rows.Scan(&r.ID, &r.IntentID, &r.InteractionID, &r.Time, &r.ThreatCode, &r.Message); err != nil {
			return nil, 0, err
		}
		result = append(result, r)
	}
	return result, total, nil
}

func (d *DB) GetThreatByID(id string) (*ThreatRecord, error) {
	r := &ThreatRecord{}
	err := d.conn.QueryRow(`
		SELECT id, intent_id, interaction_id, time, threat_code, message
		FROM threats WHERE id = $1`, id).
		Scan(&r.ID, &r.IntentID, &r.InteractionID, &r.Time, &r.ThreatCode, &r.Message)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (d *DB) StoreThreat(id, intentID, interactionID string, threatCode int, message string, t time.Time) error {
	_, err := d.conn.Exec(`
		INSERT INTO threats (id, intent_id, interaction_id, time, threat_code, message)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO NOTHING`,
		id, intentID, interactionID, t, threatCode, message,
	)
	return err
}

func (d *DB) GetThreatsByIntent(intentID string) ([]*ThreatRecord, error) {
	rows, err := d.conn.Query(`
		SELECT id, intent_id, interaction_id, time, threat_code, message
		FROM threats
		WHERE intent_id = $1
		ORDER BY time ASC`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*ThreatRecord
	for rows.Next() {
		r := &ThreatRecord{}
		if err := rows.Scan(&r.ID, &r.IntentID, &r.InteractionID, &r.Time, &r.ThreatCode, &r.Message); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
