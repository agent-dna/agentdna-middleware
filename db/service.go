package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
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
		`SELECT did, organization_id, api_key, email, password FROM new_admins WHERE email = $1`, email,
	).Scan(&a.DID, &orgID, &apiKey, &a.Email, &a.PasswordHash)
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
			AND did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1)`,
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
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1)
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
		WHERE a.organization_id = $2
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $2)
			AND (
				(a.deployer_did = $1 AND a.deployer_did != '')
				OR a.did IN (
					SELECT json_array_elements_text(COALESCE(u.agent_access_list, '[]')::json)
					FROM new_org_users u WHERE u.did = $1
				)
			)`,
		userDID, orgID,
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
		WHERE a.organization_id = $2
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $2)
			AND (
				(a.deployer_did = $1 AND a.deployer_did != '')
				OR a.did IN (
					SELECT json_array_elements_text(COALESCE(u.agent_access_list, '[]')::json)
					FROM new_org_users u WHERE u.did = $1
				)
			)
		GROUP BY a.did, a.name, a.created_at, a.deployer_did, a.policy
		ORDER BY a.did
		LIMIT $3 OFFSET $4`,
		userDID, orgID, limit, offset,
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
          (a.deployer_did = $1 AND a.deployer_did != '')
          OR a.did IN (
              SELECT json_array_elements_text(COALESCE(u.agent_access_list,'[]')::json)
              FROM new_org_users u WHERE u.did = $1
          )
      )
),
user_intents AS (
    SELECT DISTINCT ni.intent_id
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
	err := d.conn.QueryRow(userScopeIntentsCTE+`
		SELECT
			(SELECT COUNT(*) FROM user_agents),
			(SELECT COUNT(*) FROM user_intents),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND intent_id IN (SELECT intent_id FROM user_intents)),
			(SELECT COUNT(*) FROM new_interactions WHERE organization_id = $2 AND threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents))
		`,
		userDID, orgID,
	).Scan(&m.AgentCount, &m.IntentCount, &m.InteractionsCount, &m.ThreatCount)
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
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(i.interaction_id)                                                  AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN i.interacted_to_did END) AS tools_count,
		       SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                           AS threat_count,
		       MIN(i.time)                                                               AS first_interaction_at,
		       MAX(i.time)                                                               AS last_interaction_at
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
			&r.StartedAt, &endedAt, &r.Status, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth,
			&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount, &r.ThreatCount,
			&firstAt, &lastAt,
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
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
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
		WHERE organization_id = $2 AND threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents)`,
		userDID, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetThreatsByUser(userDID, orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(userScopeIntentsCTE+`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
		FROM new_interactions
		WHERE organization_id = $2 AND threat = 1 AND intent_id IN (SELECT intent_id FROM user_intents)
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

func (d *DB) CountUsersByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM new_org_users WHERE organization_id = $1`, orgID).Scan(&total)
	return total, err
}

func (d *DB) GetUsersByOrg(orgID string, limit, offset int) ([]*UserDetailRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			u.did,
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
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
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
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
		FROM new_interactions
		WHERE organization_id = $1 AND intent_id = $2
		ORDER BY time DESC
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
		`SELECT COUNT(*) FROM new_interactions WHERE organization_id = $1 AND threat = 1`, orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetThreatsByOrg(orgID string, limit, offset int) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
		FROM new_interactions
		WHERE organization_id = $1 AND threat = 1
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

func (d *DB) CountTopThreatAgentsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT a.did)
		FROM new_agents a
		JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.organization_id = $1
			AND i.threat = 1
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1)`,
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
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1)
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
			AND a.did NOT IN (SELECT did FROM new_org_users WHERE organization_id = $1)
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
			COALESCE(u.api_key, ''),
			COALESCE(u.organization_id, ''),
			COALESCE(u.created_at::TEXT, ''),
			COALESCE(a.email, '')
		FROM new_org_users u
		LEFT JOIN new_admins a ON a.organization_id = u.organization_id
		WHERE u.email = $1`,
		email,
	).Scan(&p.Name, &p.Email, &p.APIKey, &p.OrganizationID, &p.CreatedAt, &p.AdminEmail)
	if err != nil {
		return nil, err
	}
	return p, nil
}

type AdminProfile struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
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
	).Scan(&p.Name, &p.Email, &p.OrganizationID, &p.APIKey, &p.AgentCount, &p.IntentCount, &p.ThreatCount, &p.TotalUsers, &createdAt)
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

func (d *DB) StoreOrgUser(nftID, did, orgID, name, email, passwordHash string) error {
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
	var didVal interface{}
	if did != "" {
		didVal = did
	}
	_, err := d.conn.Exec(
		`INSERT INTO new_org_users (nft_id, did, organization_id, name, email, password) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
		nftID, didVal, orgID, name, email, passwordHash,
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

func (d *DB) StoreNewAgent(nftID, did, deployerDID, orgID, policy, agentName string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_agents (nft_id, did, deployer_did, organization_id, policy, name) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
		nftID, did, deployerDID, orgID, policy, agentName,
	)
	return err
}

func (d *DB) GetAgentOrgID(agentDID string) (string, error) {
	var orgID sql.NullString
	err := d.conn.QueryRow(`SELECT organization_id FROM new_agents WHERE did = $1`, agentDID).Scan(&orgID)
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

func (d *DB) StoreNewInteraction(id, initiatorDID, initiatorName, interactedToDID, interactedToName, interactionType, direction string, threat bool, intentID, orgID, message string, eventTime time.Time) error {
	threatInt := 0
	if threat {
		threatInt = 1
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	_, err := d.conn.Exec(
		`INSERT INTO new_interactions
		 (interaction_id, initiator_did, initiator_name, interacted_to_did, interacted_to_name, type, direction, threat, intent_id, organization_id, message, time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING`,
		id, initiatorDID, initiatorName, interactedToDID, interactedToName, interactionType, direction, threatInt, intentID, orgID, message, eventTime,
	)
	return err
}

func (d *DB) StoreIntent(intentID, initiatorDID, orgID, flowType, executor string, chainDepth int, threatDetected bool, interactionIDs []string) error {
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
		 (intent_id, initiator_did, organization_id, interaction_ids, status, threat_detected, flow_type, executor, chain_depth)
		 VALUES ($1, $2, $3, $4, 'completed', $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
		intentID, initiatorDID, orgID, string(interactionIDsJSON), threatInt, flowType, executor, chainDepth,
	)
	return err
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
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
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
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0),
		       COUNT(i.interaction_id)                                                AS interactions_count,
		       COUNT(DISTINCT CASE WHEN a.did IS NOT NULL THEN i.interacted_to_did END) AS agents_count,
		       COUNT(DISTINCT CASE WHEN t.did IS NOT NULL THEN i.interacted_to_did END) AS tools_count,
		       SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)                          AS threat_count,
		       MIN(i.time)                                                             AS first_interaction_at,
		       MAX(i.time)                                                             AS last_interaction_at
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
			&r.StartedAt, &endedAt, &r.Status, &threatInt,
			&r.FlowType, &r.Executor, &r.ChainDepth,
			&r.InteractionsCount, &r.AgentsCount, &r.ToolsCount, &r.ThreatCount,
			&firstAt, &lastAt,
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
		SELECT DISTINCT ni.intent_id, ni.initiator_did, COALESCE(u.name, ''), ni.started_at,
		       ni.ended_at, ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0)
		FROM new_intents ni
		JOIN new_interactions i ON i.intent_id = ni.intent_id
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
		WHERE i.initiator_did = $1 AND ni.organization_id = $2
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
		SELECT ni.intent_id, ni.initiator_did, COALESCE(u.name, ''), ni.started_at, ni.ended_at,
		       ni.status, ni.threat_detected,
		       COALESCE(ni.flow_type, ''), COALESCE(ni.executor, 'user'), COALESCE(ni.chain_depth, 0)
		FROM new_intents ni
		LEFT JOIN new_org_users u ON u.did = ni.initiator_did
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
			&r.FlowType, &r.Executor, &r.ChainDepth,
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
			END                                                                  AS score
		FROM new_agents a
		LEFT JOIN new_interactions i ON i.initiator_did = a.did
		WHERE a.did = $1
		GROUP BY a.did, a.name, a.created_at, a.deployer_did, a.policy`,
		agentDID,
	).Scan(&r.AgentDID, &r.AgentName, &r.CreatedAt, &r.DeployerDID, &r.Policy,
		&r.TotalInteractions, &r.TotalThreats, &r.Score)
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
		       COALESCE(NULLIF(u.name, ''), NULLIF(ag_init.name, ''), ''),
		       COALESCE(ni.organization_id, ''),
		       ni.started_at, ni.ended_at, ni.status, ni.threat_detected,
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
		&r.StartedAt, &endedAt, &r.Status, &threatInt,
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

func (d *DB) GetInteractionsByIntent(intentID string) ([]*InteractionRecord, error) {
	rows, err := d.conn.Query(`
		SELECT interaction_id,
		       initiator_did, COALESCE(initiator_name, ''),
		       interacted_to_did, COALESCE(interacted_to_name, ''),
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
		FROM new_interactions WHERE intent_id = $1 ORDER BY time ASC`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInteractionNewRows(rows)
}

func (d *DB) StoreNewTool(did, name, orgID string) error {
	_, err := d.conn.Exec(
		`INSERT INTO new_tools (did, name, organization_id) VALUES ($1, $2, $3) ON CONFLICT (did) DO NOTHING`,
		did, name, orgID,
	)
	return err
}

func (d *DB) CountToolsByOrg(orgID string) (int, error) {
	var total int
	err := d.conn.QueryRow(`
		SELECT COUNT(DISTINCT t.did) FROM new_tools t
		INNER JOIN new_interactions i ON i.interacted_to_did = t.did AND i.organization_id = $1`,
		orgID,
	).Scan(&total)
	return total, err
}

func (d *DB) GetToolsByOrg(orgID string, limit, offset int) ([]*ToolRecord, error) {
	rows, err := d.conn.Query(`
		SELECT
			t.did,
			t.name,
			COUNT(i.interaction_id)                          AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)   AS total_threats,
			COUNT(DISTINCT i.intent_id)                      AS total_intents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                              AS score
		FROM new_tools t
		INNER JOIN new_interactions i ON i.interacted_to_did = t.did AND i.organization_id = $1
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
			COUNT(i.interaction_id)                          AS total_interactions,
			SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END)   AS total_threats,
			COUNT(DISTINCT i.intent_id)                      AS total_intents,
			CASE
				WHEN COUNT(i.interaction_id) = 0 THEN 100.0
				ELSE ROUND(CAST(
					(1.0 - SUM(CASE WHEN i.threat = 1 THEN 1 ELSE 0 END) * 1.0
					/ COUNT(i.interaction_id)) * 100 AS NUMERIC), 2)
			END                                              AS score
		FROM new_tools t
		LEFT JOIN new_interactions i ON i.interacted_to_did = t.did AND i.organization_id = $1
		WHERE t.did = $2
		GROUP BY t.did, t.name`,
		orgID, toolDID,
	).Scan(&r.DID, &r.Name, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents, &r.Score)
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
		       COALESCE(type, ''), COALESCE(direction, ''), threat, intent_id, time, COALESCE(message, '')
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
		if err := rows.Scan(&r.DID, &r.Name, &r.TotalInteractions, &r.TotalThreats, &r.TotalIntents, &r.Score); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (d *DB) StoreIntentBlockData(r *IntentBlockRecord) error {
	trustJSON, _ := json.Marshal(r.TrustIssues)
	threatInt := 0
	if r.ThreatDetected {
		threatInt = 1
	}
	createdAt := r.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := d.conn.Exec(`
		INSERT INTO intent_block_data
		  (id, intent_id, block_index, agent_did, agent_name, direction, block_type,
		   message, response, delegate_to, received_from, cbac_app, cbac_decision,
		   threat_detected, trust_issues, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (id) DO NOTHING`,
		r.ID, r.IntentID, r.BlockIndex, r.AgentDID, r.AgentName, r.Direction, r.BlockType,
		r.Message, r.Response, r.DelegateTo, r.ReceivedFrom, r.CbacApp, r.CbacDecision,
		threatInt, string(trustJSON), createdAt,
	)
	return err
}

func (d *DB) GetIntentBlocksByIntent(intentID string) ([]*IntentBlockRecord, error) {
	rows, err := d.conn.Query(`
		SELECT id, intent_id, block_index, agent_did, agent_name, direction, block_type,
		       message, response, delegate_to, received_from, cbac_app, cbac_decision,
		       threat_detected, trust_issues, created_at
		FROM intent_block_data
		WHERE intent_id = $1
		ORDER BY block_index ASC`,
		intentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*IntentBlockRecord
	for rows.Next() {
		r := &IntentBlockRecord{}
		var threatInt int
		var trustJSON string
		if err := rows.Scan(
			&r.ID, &r.IntentID, &r.BlockIndex, &r.AgentDID, &r.AgentName,
			&r.Direction, &r.BlockType, &r.Message, &r.Response,
			&r.DelegateTo, &r.ReceivedFrom, &r.CbacApp, &r.CbacDecision,
			&threatInt, &trustJSON, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		r.ThreatDetected = threatInt == 1
		_ = json.Unmarshal([]byte(trustJSON), &r.TrustIssues)
		result = append(result, r)
	}
	return result, nil
}
