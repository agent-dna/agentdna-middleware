package db

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// warningsLockNamespace is the pg_advisory_xact_lock namespace serializing
// RecomputeWarnings. Distinct from intentLockNamespace.
const warningsLockNamespace = 7302

// WarningFact is one auth_evidence row of an interaction, with what the
// warning rules need to know about it. An interaction with no evidence has a
// single fact with only InteractionID and Time set, so its warnings still get
// recomputed (to none).
type WarningFact struct {
	InteractionID string
	Time          time.Time // the interaction's time

	Destination string // raw, from a server_out row only; "" otherwise
	TrustStatus string // of the resource Destination groups under (resource_for_url)

	CredentialID            string
	CredentialStatus        string       // active (no row) | flagged | compromised
	CredentialResourceCount int          // distinct resources this credential was ever sent to
	CredentialFirstUse      sql.NullTime // earliest evidence of this credential
}

// WarningCount is how many interactions carry warning Code.
type WarningCount struct {
	Code  int64
	Count int
}

// GetWarningCountsByIntent returns, per intent, how many of its interactions
// carry each warning code, lowest code first. Intents with no warnings are
// absent from the map.
func (d *DB) GetWarningCountsByIntent(intentIDs []string) (map[string][]WarningCount, error) {
	out := map[string][]WarningCount{}
	if len(intentIDs) == 0 {
		return out, nil
	}
	rows, err := d.conn.Query(`
		SELECT ni.intent_id, w.code, COUNT(*)
		FROM new_interactions ni
		CROSS JOIN LATERAL unnest(ni.warning_codes) AS w(code)
		WHERE ni.intent_id = ANY($1)
		GROUP BY ni.intent_id, w.code
		ORDER BY ni.intent_id, w.code`,
		pq.Array(intentIDs),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var w WarningCount
		if err := rows.Scan(&id, &w.Code, &w.Count); err != nil {
			return nil, err
		}
		out[id] = append(out[id], w)
	}
	return out, rows.Err()
}

// GetWarningCountsByInitiator returns how many interactions initiated by did
// carry each warning code, lowest code first. The same interactions
// GetAgentInfo counts threats over.
func (d *DB) GetWarningCountsByInitiator(did string) ([]WarningCount, error) {
	rows, err := d.conn.Query(`
		SELECT w.code, COUNT(*)
		FROM new_interactions ni
		CROSS JOIN LATERAL unnest(ni.warning_codes) AS w(code)
		WHERE ni.initiator_did = $1
		GROUP BY w.code
		ORDER BY w.code`,
		did,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WarningCount{}
	for rows.Next() {
		var w WarningCount
		if err := rows.Scan(&w.Code, &w.Count); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// RecomputeWarnings rebuilds warning_codes for every interaction in scope:
//
//   - interactions whose signature is in signatures,
//   - interactions that called resourceID (when not ""),
//   - interactions that used credentialID (when not ""),
//   - plus every interaction sharing a credential with any of the above, since
//     credential-wide rules (5105, 5108) can change for them too.
//
// compute is given each interaction's facts and returns the codes it should
// carry. The whole run holds one advisory lock, so two recomputes never
// interleave: callers commit their own writes first, and whichever recompute
// runs second reads both. Returns how many interactions changed.
func (d *DB) RecomputeWarnings(signatures []string, resourceID, credentialID string, compute func(facts []WarningFact) []int64) (int, error) {
	if signatures == nil {
		signatures = []string{}
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1, 0)`, warningsLockNamespace); err != nil {
		return 0, fmt.Errorf("lock warnings: %w", err)
	}

	rows, err := tx.Query(`
		WITH seed AS (
			SELECT unnest($1::text[]) AS sig
			UNION
			SELECT e.request_id FROM auth_evidence e
			CROSS JOIN LATERAL resource_for_url(e.destination) r
			WHERE $2 <> '' AND e.source = 'server_out' AND COALESCE(e.destination, '') <> '' AND r.resource_id = $2
			UNION
			SELECT request_id FROM auth_evidence WHERE $3 <> '' AND credential_id = $3
		),
		seed_creds AS (
			SELECT DISTINCT credential_id FROM auth_evidence
			WHERE request_id IN (SELECT sig FROM seed) AND COALESCE(credential_id, '') <> ''
		),
		scope AS (
			SELECT sig FROM seed
			UNION
			SELECT request_id FROM auth_evidence WHERE credential_id IN (SELECT credential_id FROM seed_creds)
		),
		scope_creds AS (
			SELECT DISTINCT credential_id FROM auth_evidence
			WHERE request_id IN (SELECT sig FROM scope) AND COALESCE(credential_id, '') <> ''
		),
		cred AS (
			SELECT e.credential_id,
			       COUNT(DISTINCT r.resource_id) FILTER (WHERE e.source = 'server_out' AND r.resource_id <> '') AS resource_count,
			       MIN(e.observed_at) AS first_use
			FROM auth_evidence e
			CROSS JOIN LATERAL resource_for_url(e.destination) r
			WHERE e.credential_id IN (SELECT credential_id FROM scope_creds)
			GROUP BY e.credential_id
		)
		SELECT ni.interaction_id, ni.time,
		       -- Only server_out names a called service: server_in carries the
		       -- server's own DID and client_out the local hop (127.0.0.1).
		       CASE WHEN e.source = 'server_out' THEN COALESCE(e.destination, '') ELSE '' END,
		       COALESCE(r.trust_status, ''),
		       COALESCE(e.credential_id, ''), COALESCE(c.status, 'active'),
		       COALESCE(cr.resource_count, 0), cr.first_use
		FROM new_interactions ni
		LEFT JOIN auth_evidence e ON e.request_id = ni.signature
		LEFT JOIN LATERAL resource_for_url(e.destination) r ON TRUE
		LEFT JOIN credentials c ON c.credential_id = e.credential_id
		LEFT JOIN cred cr ON cr.credential_id = e.credential_id
		WHERE ni.signature <> '' AND ni.signature IN (SELECT sig FROM scope)
		ORDER BY ni.interaction_id`,
		pq.Array(signatures), resourceID, credentialID,
	)
	if err != nil {
		return 0, fmt.Errorf("load warning facts: %w", err)
	}
	byInteraction := map[string][]WarningFact{}
	var order []string
	for rows.Next() {
		var f WarningFact
		if err := rows.Scan(&f.InteractionID, &f.Time, &f.Destination, &f.TrustStatus,
			&f.CredentialID, &f.CredentialStatus, &f.CredentialResourceCount, &f.CredentialFirstUse); err != nil {
			rows.Close()
			return 0, err
		}
		if _, seen := byInteraction[f.InteractionID]; !seen {
			order = append(order, f.InteractionID)
		}
		byInteraction[f.InteractionID] = append(byInteraction[f.InteractionID], f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(order) == 0 {
		return 0, tx.Commit()
	}

	// One batched UPDATE: ids[i] gets codes[i], an int[] literal like "{5101,5105}".
	ids := make([]string, 0, len(order))
	codes := make([]string, 0, len(order))
	for _, id := range order {
		list := compute(byInteraction[id])
		parts := make([]string, len(list))
		for i, c := range list {
			parts[i] = strconv.FormatInt(c, 10)
		}
		ids = append(ids, id)
		codes = append(codes, "{"+strings.Join(parts, ",")+"}")
	}
	res, err := tx.Exec(`
		UPDATE new_interactions ni SET warning_codes = v.codes::int[]
		FROM unnest($1::text[], $2::text[]) AS v(id, codes)
		WHERE ni.interaction_id = v.id AND ni.warning_codes IS DISTINCT FROM v.codes::int[]`,
		pq.Array(ids), pq.Array(codes),
	)
	if err != nil {
		return 0, fmt.Errorf("save warning codes: %w", err)
	}
	changed, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(changed), nil
}

// AutoFlaggedBy is the updated_by a credential gets when FlagCredentialOnRejections
// flags it, so the dashboard can tell it apart from an admin's change.
const AutoFlaggedBy = "system"

// FlagCredentialOnRejections flags credential id once more than limit of its
// requests were rejected, which in turn gives its interactions warning 5107.
// It reports whether it flagged the key now, and how many rejections it counted.
//
// Rejections are counted per request (a request seen as rejected by both the
// gateway and the server counts once), and only since the key's status was
// last set. So when an admin sets a flagged key back to active, the count
// starts again rather than flagging it on the next rejection.
//
// Only an active key (or one with no status yet) is flagged. A key already
// flagged or compromised is left as it is. The status write and the check
// happen in one statement, so concurrent batches flag a key at most once.
func (d *DB) FlagCredentialOnRejections(id string, limit int) (flagged bool, rejections int, err error) {
	if id == "" || limit <= 0 {
		return false, 0, nil
	}
	err = d.conn.QueryRow(`
		WITH cur AS (
			SELECT status, updated_at FROM credentials WHERE credential_id = $1
		), n AS (
			SELECT COUNT(DISTINCT e.request_id)::int AS rejections
			FROM auth_evidence e
			WHERE e.credential_id = $1
			  AND lower(btrim(COALESCE(e.auth_status, ''))) = 'rejected'
			  AND (NOT EXISTS (SELECT 1 FROM cur) OR e.observed_at > (SELECT updated_at FROM cur))
		), ins AS (
			INSERT INTO credentials (credential_id, status, reason, updated_by, updated_at)
			SELECT $1, 'flagged',
			       format('Automatically flagged: %s rejected requests since the last status change (limit %s).', n.rejections, $2::int),
			       $3, NOW()
			FROM n
			WHERE n.rejections > $2::int
			  AND COALESCE((SELECT status FROM cur), 'active') = 'active'
			ON CONFLICT (credential_id) DO UPDATE SET
				status = EXCLUDED.status, reason = EXCLUDED.reason,
				updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
				WHERE credentials.status = 'active'
			RETURNING 1
		)
		SELECT EXISTS (SELECT 1 FROM ins), (SELECT rejections FROM n)`,
		id, limit, AutoFlaggedBy,
	).Scan(&flagged, &rejections)
	return flagged, rejections, err
}
