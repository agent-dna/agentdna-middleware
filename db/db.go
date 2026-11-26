package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type OrgMetrics struct {
	AgentCount                 int
	IntentCount                int
	InteractionsCount          int
	ThreatCount                int
	AppCount                   int
	AgentCount24hChange        int
	IntentCount24hChange       int
	InteractionsCount24hChange int
	ThreatCount24hChange       int
	AppCount24hChange          int
}

type AdminRecord struct {
	DID            string
	OrganizationID string
	APIKey         string
	Email          string
	Name           string
}

type RequestRecord struct {
	RequestID   string
	RequestType string
	Policy      string
	CreatorDID  string
	AgentDID    string
	AgentName   string
	RequestInfo string
	OrgID       string
	Status      string
	CreatedAt   time.Time
}

type AgentDetailRecord struct {
	AgentDID          string
	AgentName         string
	CreatedAt         time.Time
	DeployerDID       string
	Policy            string
	TotalInteractions int
	TotalThreats      int
	Score             float64
	Revoked           bool
}

type UserDetailRecord struct {
	UserDID          string
	UserName         string
	CreatedAt        time.Time
	TotalIntents     int
	TotalThreats     int
	AccessAgentCount int
}

type InteractionRecord struct {
	InteractionID string
	From          string
	FromName      string
	To            string
	ToName        string
	Type          string
	Direction     string
	Threat        bool
	ThreatID      string
	ThreatCode    int
	ThreatTitle   string
	IntentID      string
	Message       string
	Signature     string
	ReviewStatus  string
	Time          time.Time
	WarningCodes  []int64 // 51xx codes, see RecomputeWarnings
}

type ThreatRecord struct {
	ID            string
	IntentID      string
	InteractionID string
	Time          time.Time
	ThreatCode    int
	Message       string
}

type ThreatCodeRecord struct {
	Code        int
	Title       string
	Severity    string
	Description string
}

type TopThreatRecord struct {
	ThreatCode int // UnknownThreatCode for codes not in threat_codes
	Title      string
	Severity   string
	Count      int
}

type IntentRecord struct {
	IntentID           string
	InitiatorDID       string
	InitiatorName      string
	OrgID              string
	StartedAt          time.Time
	EndedAt            *time.Time
	Status             string
	ReviewStatus       string
	ThreatDetected     bool
	FlowType           string
	Executor           string
	ChainDepth         int
	InteractionsCount  int
	AgentsCount        int
	ToolsCount         int
	Apps               IntentApps // distinct new_tools entries the intent called; same set ToolsCount counts
	ThreatCount        int
	FirstInteractionAt *time.Time
	LastInteractionAt  *time.Time
	RuntimeSeconds     float64
	Title              string
}

// IntentApp is one app (new_tools row) an intent called.
type IntentApp struct {
	DID  string `json:"did"`
	Name string `json:"name"`
}

// IntentApps scans the JSONB array of {did, name} objects the intent queries
// aggregate per intent.
type IntentApps []IntentApp

func (a *IntentApps) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	case nil:
		*a = IntentApps{}
		return nil
	default:
		return fmt.Errorf("IntentApps: unsupported type %T", src)
	}
	return json.Unmarshal(b, a)
}

// DIDs returns just the app DIDs, never nil.
func (a IntentApps) DIDs() []string {
	dids := make([]string, 0, len(a))
	for _, app := range a {
		dids = append(dids, app.DID)
	}
	return dids
}

type ToolRecord struct {
	DID               string
	Name              string
	TotalInteractions int
	TotalThreats      int
	TotalIntents      int
	TotalAgents       int
	Score             float64
	LastInteractedAt  *time.Time
	AgentsList        []string
}

type UserInfoRecord struct {
	UserDID           string   // primary (latest) DID
	DIDs              []string // every DID the user holds, oldest first
	UserName          string
	DisplayName       string
	CreatedAt         time.Time
	LastActive        *time.Time
	IsActive          bool
	AccessAgentCount  int
	TotalInteractions int
	TotalThreats      int
	TotalIntents      int
	TotalAgentsOwned  int
}

type UserAgentRecord struct {
	AgentDID          string
	AgentName         string
	CreatedAt         time.Time
	TotalInteractions int
	TotalThreats      int
	Score             float64
}

// UserAppRecord is one app (tool) reached in a user's intents.
type UserAppRecord struct {
	AppDID            string
	AppName           string
	TotalInteractions int
	TotalThreats      int
	IntentsCount      int
	LastUsed          time.Time
}

type SearchAgentResult struct {
	DID   string
	Name  string
	OrgID string
}

type SearchAppResult struct {
	DID  string
	Name string
}

type SearchIntentResult struct {
	IntentID       string
	FlowType       string
	Status         string
	ThreatDetected bool
	StartedAt      time.Time
}

type SearchResults struct {
	Agents  []SearchAgentResult
	Apps    []SearchAppResult
	Intents []SearchIntentResult
}

type AgentVolumeRecord struct {
	AgentDID          string
	AgentNFTID        string
	AgentName         string
	TotalInteractions int
	TotalThreats      int
}

type OrgUserRecord struct {
	DID             string
	OrganizationID  string
	APIKey          string
	NFTID           string
	Name            string
	Email           string
	PasswordHash    string
	Policy          string
	AgentCount      int
	IntentCount     int
	ThreatCount     int
	AgentAccessList []string
	Key             string
}

type DB struct {
	conn *sql.DB
}

func New(dsn string) *DB {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}

	if err := conn.Ping(); err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}

	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS new_admins (
			did             TEXT PRIMARY KEY,
			organization_id TEXT,
			api_key         TEXT,
			email           TEXT,
			agent_count     INTEGER DEFAULT 0,
			intent_count    INTEGER DEFAULT 0,
			threat_count    INTEGER DEFAULT 0,
			total_users     INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS new_org_users (
			did               TEXT DEFAULT '',
			organization_id   TEXT,
			api_key           TEXT,
			nft_id            TEXT,
			name              TEXT DEFAULT '',
			email             TEXT PRIMARY KEY,
			password          TEXT,
			policy            TEXT DEFAULT '',
			agent_count       INTEGER DEFAULT 0,
			intent_count      INTEGER DEFAULT 0,
			threat_count      INTEGER DEFAULT 0,
			agent_access_list TEXT DEFAULT '[]',
			created_at        TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS new_agents (
			did                TEXT PRIMARY KEY,
			name               TEXT DEFAULT '',
			deployer_did       TEXT,
			organization_id    TEXT,
			nft_id             TEXT,
			policy             TEXT,
			interactions_count INTEGER DEFAULT 0,
			intent_count       INTEGER DEFAULT 0,
			threat_count       INTEGER DEFAULT 0,
			created_at         TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS new_requests (
			request_id      TEXT PRIMARY KEY,
			request_type    TEXT,
			policy          TEXT,
			creator_did     TEXT,
			agent_did       TEXT DEFAULT '',
			agent_name      TEXT DEFAULT '',
			request_info    TEXT DEFAULT '',
			organization_id TEXT DEFAULT '',
			status          TEXT DEFAULT 'pending',
			created_at      TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS new_interactions (
			interaction_id    TEXT PRIMARY KEY,
			initiator_did     TEXT DEFAULT '',
			initiator_name    TEXT DEFAULT '',
			interacted_to_did TEXT DEFAULT '',
			interacted_to_name TEXT DEFAULT '',
			type              TEXT DEFAULT '',
			direction         TEXT DEFAULT '',
			threat            INTEGER DEFAULT 0,
			intent_id         TEXT DEFAULT '',
			organization_id   TEXT DEFAULT '',
			time              TIMESTAMPTZ DEFAULT NOW()
		);
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS type TEXT DEFAULT '';
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS direction TEXT DEFAULT '';
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';
		-- JSON (not JSONB): JSON keeps the input text exactly, JSONB reorders keys
		-- and strips whitespace. raw_data must be the envelope exactly as received.
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS raw_data JSON NOT NULL DEFAULT '{}'::json;
		DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns
			           WHERE table_name = 'new_interactions' AND column_name = 'raw_data' AND data_type = 'jsonb') THEN
				ALTER TABLE new_interactions ALTER COLUMN raw_data DROP DEFAULT;
				ALTER TABLE new_interactions ALTER COLUMN raw_data TYPE JSON USING raw_data::json;
				ALTER TABLE new_interactions ALTER COLUMN raw_data SET DEFAULT '{}'::json;
			END IF;
		END $$;
		ALTER TABLE new_interactions DROP COLUMN IF EXISTS provenance_req_id;
		ALTER TABLE new_interactions DROP COLUMN IF EXISTS provenance_record_id;
		DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name='new_interactions' AND column_name='block_type'
			) THEN
				UPDATE new_interactions SET type = block_type WHERE type = '' OR type IS NULL;
				ALTER TABLE new_interactions DROP COLUMN block_type;
			END IF;
		END $$;
		CREATE TABLE IF NOT EXISTS new_intents (
			intent_id        TEXT PRIMARY KEY,
			interaction_ids  TEXT DEFAULT '[]',
			initiator_did    TEXT DEFAULT '',
			organization_id  TEXT DEFAULT '',
			started_at       TIMESTAMPTZ DEFAULT NOW(),
			ended_at         TIMESTAMPTZ,
			status           TEXT DEFAULT 'running',
			threat_detected  INTEGER DEFAULT 0,
			flow_type        TEXT DEFAULT '',
			executor         TEXT DEFAULT 'user',
			chain_depth      INTEGER DEFAULT 0
		);
		ALTER TABLE new_intents DROP COLUMN IF EXISTS provenance_req_id;
		ALTER TABLE new_intents DROP COLUMN IF EXISTS provenance_record_id;
		-- Review status: distinct from the workflow "status" column above.
		-- Tracks human triage of the intent: Unreviewed -> Acknowledged | Flagged.
		ALTER TABLE new_intents ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'Unreviewed';
		-- 'Ongoing' was renamed to 'Unreviewed': move the column default and any
		-- existing rows over so old and new intents read the same.
		ALTER TABLE new_intents ALTER COLUMN review_status SET DEFAULT 'Unreviewed';
		UPDATE new_intents SET review_status = 'Unreviewed' WHERE review_status = 'Ongoing' OR review_status IS NULL;
		-- Initiator display name, resolved at ingest the same way each
		-- interaction's initiator_name is. Read queries prefer the live
		-- new_org_users/new_agents name and fall back to this, so the intent
		-- never shows a blank name the interactions themselves have.
		ALTER TABLE new_intents ADD COLUMN IF NOT EXISTS initiator_name TEXT DEFAULT '';
		UPDATE new_intents ni SET initiator_name = sub.name
		FROM (
			SELECT DISTINCT ON (i.intent_id) i.intent_id, i.initiator_name AS name
			FROM new_interactions i
			JOIN new_intents x ON x.intent_id = i.intent_id AND x.initiator_did = i.initiator_did
			WHERE COALESCE(i.initiator_name, '') <> ''
			ORDER BY i.intent_id, i.time ASC
		) sub
		WHERE ni.intent_id = sub.intent_id AND COALESCE(ni.initiator_name, '') = '';
		CREATE TABLE IF NOT EXISTS new_tools (
			did             TEXT PRIMARY KEY,
			name            TEXT,
			organization_id TEXT
		);
		-- pending_branches: short-lived bridge between the two separate HTTP
		-- calls of one on-chain txn (/rubix/v1/tx then /rubix/v1/signature).
		-- Since intent_id is now the nftId shared across every txn/branch for
		-- that intent, we can no longer use intent_id to find "the rows this
		-- particular txn call just inserted" once /signature responds — this
		-- table is that lookup, keyed by the /tx response's result.id, and is
		-- deleted (either way) as soon as /signature resolves.
		CREATE TABLE IF NOT EXISTS pending_branches (
			req_id     TEXT PRIMARY KEY,
			intent_id  TEXT NOT NULL,
			payload    TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		-- How each request authenticated, as seen at one observation point.
		-- No credential value is ever stored here, only keyed fingerprints.
		--
		-- identity_id is deliberately NULLable. NULL means the credential was
		-- opaque and we cannot tell whose it is, which is not the same as
		-- nothing having been observed. Collapsing the two makes the analysis
		-- claim an identity change it never saw.
		--
		-- The key is (request_id, source, destination). One request is seen by
		-- more than one point - a server records what arrived and what it then
		-- sent onward - and one server can call several backends while serving
		-- it. Without source and destination in the key, all but the first of
		-- those rows would be dropped.
		CREATE TABLE IF NOT EXISTS auth_evidence (
			request_id      TEXT NOT NULL,
			source          TEXT NOT NULL,
			run_id          TEXT DEFAULT '',
			auth_method     TEXT DEFAULT '',
			credential_id   TEXT DEFAULT '',
			identity_id     TEXT,
			identity_name   TEXT,
			auth_status     TEXT DEFAULT 'unknown',
			key_version     TEXT DEFAULT '',
			destination     TEXT DEFAULT '',
			organization_id TEXT DEFAULT '',
			observed_at     TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (request_id, source, destination)
		);
		CREATE INDEX IF NOT EXISTS auth_evidence_run_idx ON auth_evidence (run_id);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Runtime migrations for existing databases.
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE`)
	conn.Exec(`ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS message TEXT DEFAULT ''`)
	conn.Exec(`ALTER TABLE auth_evidence ADD COLUMN IF NOT EXISTS identity_name TEXT`)
	conn.Exec(`ALTER TABLE new_admins ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''`)
	conn.Exec(`ALTER TABLE new_admins ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
	// Admin passwords live only on the admin server; drop the old local copies.
	conn.Exec(`ALTER TABLE new_admins DROP COLUMN IF EXISTS password`)
	conn.Exec(`ALTER TABLE new_org_users ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''`)
	conn.Exec(`ALTER TABLE new_org_users ADD COLUMN IF NOT EXISTS key TEXT DEFAULT ''`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_org_users_key ON new_org_users (key)`)
	conn.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_org_users_api_key ON new_org_users (api_key) WHERE api_key IS NOT NULL AND api_key <> ''`)
	// Migrate new_org_users primary key from did → email so users can be
	// created without a DID (DID is populated later via user-did-to-key).
	conn.Exec(`ALTER TABLE new_org_users ALTER COLUMN did DROP NOT NULL`)
	conn.Exec(`ALTER TABLE new_org_users ALTER COLUMN did SET DEFAULT 'none'`)
	conn.Exec(`UPDATE new_org_users SET did = 'none' WHERE did IS NULL OR did = ''`)
	conn.Exec(`ALTER TABLE new_org_users DROP CONSTRAINT IF EXISTS new_org_users_pkey`)
	conn.Exec(`ALTER TABLE new_org_users ADD COLUMN IF NOT EXISTS email_pk_added BOOLEAN DEFAULT FALSE`)
	conn.Exec(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name='new_org_users' AND constraint_type='PRIMARY KEY') THEN ALTER TABLE new_org_users ADD PRIMARY KEY (email); END IF; END $$`)
	// user_dids: one row per user (email PRIMARY KEY) holding every DID the
	// user owns in dids, oldest first. new_org_users.did stays as the user's
	// latest/primary DID. email follows new_org_users.email via ON UPDATE
	// CASCADE (UpdateUserEmail). The user_dids_normalize trigger dedupes the
	// list and rejects a DID already held by another user (unique_violation).
	for _, stmt := range []string{
		// Convert the old one-row-per-DID layout (did PRIMARY KEY) in place.
		`DO $$ BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns
			           WHERE table_name = 'user_dids' AND column_name = 'did') THEN
				CREATE TABLE user_dids_new (
					email      TEXT PRIMARY KEY REFERENCES new_org_users(email) ON UPDATE CASCADE ON DELETE CASCADE,
					dids       TEXT[] NOT NULL DEFAULT '{}',
					created_at TIMESTAMPTZ DEFAULT NOW()
				);
				INSERT INTO user_dids_new (email, dids, created_at)
				SELECT email, array_agg(did ORDER BY created_at, did), MIN(created_at)
				FROM user_dids GROUP BY email;
				DROP TABLE user_dids;
				ALTER TABLE user_dids_new RENAME TO user_dids;
				ALTER TABLE user_dids RENAME CONSTRAINT user_dids_new_pkey TO user_dids_pkey;
				ALTER TABLE user_dids RENAME CONSTRAINT user_dids_new_email_fkey TO user_dids_email_fkey;
			END IF;
		END $$`,
		`CREATE TABLE IF NOT EXISTS user_dids (
			email      TEXT PRIMARY KEY REFERENCES new_org_users(email) ON UPDATE CASCADE ON DELETE CASCADE,
			dids       TEXT[] NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_dids_dids ON user_dids USING GIN (dids)`,
		// The advisory lock serialises writers so two users can't claim the
		// same DID concurrently.
		`CREATE OR REPLACE FUNCTION user_dids_normalize() RETURNS trigger
		 LANGUAGE plpgsql AS $$
		 DECLARE
			self_email TEXT := NEW.email;
			taken      TEXT;
		 BEGIN
			IF TG_OP = 'UPDATE' THEN
				self_email := OLD.email;
			END IF;
			NEW.dids := ARRAY(
				SELECT d FROM unnest(NEW.dids) WITH ORDINALITY AS t(d, n)
				WHERE d IS NOT NULL AND d NOT IN ('', 'none', 'default-id')
				GROUP BY d ORDER BY MIN(n));
			PERFORM pg_advisory_xact_lock(hashtext('user_dids'));
			SELECT d INTO taken
			FROM user_dids ud, unnest(ud.dids) AS d
			WHERE ud.email NOT IN (NEW.email, self_email)
			  AND ud.dids && NEW.dids AND d = ANY(NEW.dids)
			LIMIT 1;
			IF taken IS NOT NULL THEN
				RAISE EXCEPTION 'did % already registered to another user', taken
					USING ERRCODE = 'unique_violation';
			END IF;
			RETURN NEW;
		 END $$`,
		`DROP TRIGGER IF EXISTS user_dids_normalize ON user_dids`,
		`CREATE TRIGGER user_dids_normalize BEFORE INSERT OR UPDATE OF dids ON user_dids
		 FOR EACH ROW EXECUTE FUNCTION user_dids_normalize()`,
		// Backfill each user's primary DID into their list (skipping DIDs
		// another user already holds).
		`INSERT INTO user_dids (email, dids)
		 SELECT DISTINCT ON (u.did) u.email, ARRAY[u.did]
		 FROM new_org_users u
		 WHERE u.did IS NOT NULL AND u.did NOT IN ('', 'none', 'default-id')
		   AND NOT EXISTS (SELECT 1 FROM user_dids WHERE dids @> ARRAY[u.did])
		 ORDER BY u.did, u.created_at
		 ON CONFLICT (email) DO UPDATE SET dids = user_dids.dids || EXCLUDED.dids`,
		// user_did_set(did) expands any one DID to every DID its user holds.
		// An admin's DIDs are the new_admins rows sharing their admin-server
		// username. The input DID is always included, so agent
		// DIDs passed through user-scoped queries behave exactly as a plain
		// "= $1" did before.
		// A placeholder DID ('', 'none', 'default-id': a user with no real
		// DID yet) expands to nothing. Otherwise such a user would "own"
		// every agent and intent whose owner DID is that same placeholder,
		// i.e. every orphaned record.
		`CREATE OR REPLACE FUNCTION user_did_set(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT d FROM (
				SELECT unnest(dids) AS d FROM user_dids WHERE dids @> ARRAY[p_did]
				UNION
				SELECT a2.did FROM new_admins a1
				JOIN new_admins a2 ON a2.name = a1.name
				WHERE a1.did = p_did AND COALESCE(a1.name, '') <> ''
				UNION
				SELECT p_did
			) s
			WHERE COALESCE(p_did, '') NOT IN ('', 'none', 'default-id')
			  AND COALESCE(d, '') NOT IN ('', 'none', 'default-id')
		 $$`,
		// What an org user may see. Admins see the whole org and never go
		// through these. Every function takes any one of the user's DIDs.
		//
		// user_owned_agents: agents the user deployed (deployer_did, or an
		// approved deploy_agent request they created).
		`CREATE OR REPLACE FUNCTION user_owned_agents(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT a.did FROM new_agents a
			WHERE a.deployer_did IN (SELECT user_did_set(p_did))
			UNION
			SELECT r.agent_did FROM new_requests r
			WHERE r.creator_did IN (SELECT user_did_set(p_did))
			  AND r.request_type = 'deploy_agent' AND r.status = 'approved'
			  AND COALESCE(r.agent_did, '') <> ''
		 $$`,
		// user_participated_intents: intents the user personally took part
		// in — started it, or sent or received any of its interactions.
		`CREATE OR REPLACE FUNCTION user_participated_intents(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT ni.intent_id FROM new_intents ni
			WHERE ni.initiator_did IN (SELECT user_did_set(p_did))
			UNION
			SELECT ix.intent_id FROM new_interactions ix
			WHERE ix.initiator_did IN (SELECT user_did_set(p_did))
			   OR ix.interacted_to_did IN (SELECT user_did_set(p_did))
		 $$`,
		// user_intent_ids: the intents a user may see — ones they took part
		// in, plus ones any agent they deployed took part in.
		`CREATE OR REPLACE FUNCTION user_intent_ids(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT user_participated_intents(p_did)
			UNION
			SELECT ni.intent_id FROM new_intents ni
			WHERE ni.initiator_did IN (SELECT user_owned_agents(p_did))
			UNION
			SELECT ix.intent_id FROM new_interactions ix
			WHERE ix.initiator_did IN (SELECT user_owned_agents(p_did))
			   OR ix.interacted_to_did IN (SELECT user_owned_agents(p_did))
		 $$`,
		// user_visible_agents: the agents a user may see — ones they
		// deployed, plus ones they used: any agent in an intent the user
		// personally took part in. Agents that only met the user's agents
		// (another user's agent calling theirs) are not "used" and stay
		// hidden, as do agents with no owner or an unknown owner.
		`CREATE OR REPLACE FUNCTION user_visible_agents(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT user_owned_agents(p_did)
			UNION
			SELECT a.did FROM new_agents a
			JOIN new_interactions ix ON a.did IN (ix.initiator_did, ix.interacted_to_did)
			WHERE ix.intent_id IN (SELECT user_participated_intents(p_did))
		 $$`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			log.Printf("[migrate] user_dids: %v", err)
		}
	}
	// sessions: dashboard logins. token_hash is the SHA-256 of the random
	// session token the browser holds in its cookie; the raw token is never
	// stored. account_id is new_org_users.email for account_type 'user' and
	// new_admins.did for 'admin'.
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			token_hash   TEXT PRIMARY KEY,
			account_type TEXT NOT NULL,
			account_id   TEXT NOT NULL,
			ip           TEXT NOT NULL DEFAULT '',
			user_agent   TEXT NOT NULL DEFAULT '',
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at   TIMESTAMPTZ NOT NULL
		)`,
		// Early builds named account_id "email"; such sessions are dropped.
		`DO $$ BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'sessions' AND column_name = 'email') THEN
				DELETE FROM sessions;
				DROP INDEX IF EXISTS idx_sessions_account;
				ALTER TABLE sessions RENAME COLUMN email TO account_id;
			END IF;
		END $$`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions (account_type, account_id)`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			log.Printf("[migrate] sessions: %v", err)
		}
	}
	// Migrate new_tools primary key from (did, organization_id) → did.
	conn.Exec(`DELETE FROM new_tools WHERE ctid NOT IN (SELECT MIN(ctid) FROM new_tools GROUP BY did)`)
	conn.Exec(`ALTER TABLE new_tools DROP CONSTRAINT IF EXISTS new_tools_pkey`)
	conn.Exec(`ALTER TABLE new_tools ADD PRIMARY KEY (did) `)
	conn.Exec(`ALTER TABLE new_tools ALTER COLUMN organization_id DROP NOT NULL`)
	// agents_list: JSON array of agent DIDs that have contacted this tool so
	// far. Same convention as new_intents.interaction_ids — a plain TEXT
	// column holding a JSON-encoded []string, marshaled/unmarshaled in Go.
	conn.Exec(`ALTER TABLE new_tools ADD COLUMN IF NOT EXISTS agents_list TEXT DEFAULT '[]'`)
	conn.Exec(`ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS threat_id TEXT NOT NULL DEFAULT ''`)
	// warning_codes: the 51xx codes that currently apply to this interaction,
	// computed by RecomputeWarnings from its auth evidence, the destinations'
	// trust status and the credentials' status. Rebuilt whole on every
	// recompute, so a code that stops applying disappears.
	conn.Exec(`ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS warning_codes INT[] NOT NULL DEFAULT '{}'`)
	// RecomputeWarnings looks evidence up by credential.
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_auth_evidence_credential ON auth_evidence (credential_id)`)
	conn.Exec(`CREATE TABLE IF NOT EXISTS apps (
		did        TEXT PRIMARY KEY,
		name       TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)

	conn.Exec(`CREATE TABLE IF NOT EXISTS threats (
		id             TEXT PRIMARY KEY,
		intent_id      TEXT NOT NULL,
		interaction_id TEXT NOT NULL,
		time           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		threat_code    INT NOT NULL DEFAULT 0,
		message        TEXT NOT NULL DEFAULT ''
	)`)

	conn.Exec(`CREATE TABLE IF NOT EXISTS threat_codes (
		code        INT PRIMARY KEY,
		title       TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT ''
	)`)

	// Rows come from handler/error_code.json via SyncThreatCodes at startup.
	conn.Exec(`ALTER TABLE threat_codes ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT ''`)

	// Observability page: hop lookups filter/join on these columns on every
	// request (org+time window, per-intent, per-DID-pair, per-initiator).
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_org_time ON new_interactions (organization_id, time)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_intent_id ON new_interactions (intent_id)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_from_to ON new_interactions (initiator_did, interacted_to_did)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_intents_initiator ON new_intents (initiator_did)`)
	// Auth evidence is matched to its interaction by signature (request_id).
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_signature ON new_interactions (signature)`)

	// Resources: every destination a server called while serving a request
	// (auth_evidence rows with source server_out).
	//
	//   resource_bases     the known services (loaded by an ops script, ~100
	//                      rows) plus any host an admin set a trust status on.
	//                      Trust status lives here.
	//   resource_accesses  one row per (url, intent, credential) actually seen.
	//   resource_access_groups (view)
	//                      each access matched, at read time, to the base with
	//                      the same host and the longest path_prefix that its
	//                      path starts with on a "/" boundary. No match: the
	//                      access groups under its host, Unreviewed.
	//
	// Grouping is never stored, so adding or changing a base regroups all
	// past accesses at once. URLs and bases are both normalized by
	// resource_url_parts, so the two sides cannot disagree.
	//
	// The old JSONB "resources" table is no longer written or read; its trust
	// statuses are carried into resource_bases by BackfillResources.
	for _, stmt := range []string{
		// resource_url_parts("POST https://www.Atlasisin.com:443/jira/t1/?q=1#x")
		//   -> host "atlasisin.com", path "/jira/t1"
		// Drops a leading HTTP method (destinations arrive as "POST https://..."),
		// scheme, userinfo, "www.", default ports, query, fragment and trailing
		// "/"; lowercases the host. A bare host has path ''.
		`CREATE OR REPLACE FUNCTION resource_url_parts(raw TEXT, OUT host TEXT, OUT path TEXT)
		 LANGUAGE sql IMMUTABLE AS $$
			SELECT regexp_replace(regexp_replace(lower(regexp_replace(split_part(v, '/', 1), '^.*@', '')),
			                                     '^www\.', ''), ':(80|443)$', ''),
			       CASE WHEN strpos(v, '/') > 0 THEN regexp_replace(substr(v, strpos(v, '/')), '/+$', '') ELSE '' END
			FROM (SELECT regexp_replace(regexp_replace(regexp_replace(btrim(COALESCE(raw, '')),
			             '^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+', '', 'i'),
			             '^[A-Za-z][A-Za-z0-9+.-]*://', ''), '[?#].*$', '') AS v) s
		 $$`,
		`CREATE TABLE IF NOT EXISTS resource_bases (
			id           SERIAL PRIMARY KEY,
			base_url     TEXT NOT NULL,
			host         TEXT NOT NULL DEFAULT '',
			path_prefix  TEXT NOT NULL DEFAULT '',
			name         TEXT NOT NULL DEFAULT '',
			trust_status TEXT NOT NULL DEFAULT 'Unreviewed'
			             CHECK (trust_status IN ('Unreviewed', 'Flagged', 'Trusted')),
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (host, path_prefix)
		)`,
		// Fills host/path_prefix from base_url, so the ops script only
		// inserts (base_url, name) in whatever form it has the URL.
		`CREATE OR REPLACE FUNCTION resource_bases_normalize() RETURNS trigger
		 LANGUAGE plpgsql AS $$
		 BEGIN
			SELECT p.host, p.path INTO NEW.host, NEW.path_prefix FROM resource_url_parts(NEW.base_url) p;
			IF NEW.host = '' THEN
				RAISE EXCEPTION 'resource_bases: base_url % has no host', NEW.base_url
					USING ERRCODE = 'check_violation';
			END IF;
			IF COALESCE(NEW.name, '') = '' THEN
				NEW.name := NEW.host || NEW.path_prefix;
			END IF;
			RETURN NEW;
		 END $$`,
		`DROP TRIGGER IF EXISTS resource_bases_normalize ON resource_bases`,
		`CREATE TRIGGER resource_bases_normalize BEFORE INSERT OR UPDATE OF base_url ON resource_bases
		 FOR EACH ROW EXECUTE FUNCTION resource_bases_normalize()`,
		`CREATE TABLE IF NOT EXISTS resource_accesses (
			url           TEXT NOT NULL,
			host          TEXT NOT NULL,
			path          TEXT NOT NULL DEFAULT '',
			intent_id     TEXT NOT NULL,
			credential_id TEXT NOT NULL DEFAULT '',
			auth_method   TEXT NOT NULL DEFAULT '',
			first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (url, intent_id, credential_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_resource_accesses_intent ON resource_accesses (intent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_resource_accesses_host ON resource_accesses (host)`,
		`CREATE OR REPLACE VIEW resource_access_groups AS
		 SELECT ra.url, ra.host, ra.path, ra.intent_id, ra.credential_id, ra.auth_method, ra.first_seen,
		        COALESCE(b.host || b.path_prefix, ra.host)    AS resource_id,
		        COALESCE(b.name, ra.host)                     AS resource_name,
		        COALESCE(b.trust_status, 'Unreviewed')        AS trust_status
		 FROM resource_accesses ra
		 LEFT JOIN LATERAL (
			SELECT rb.host, rb.path_prefix, rb.name, rb.trust_status
			FROM resource_bases rb
			WHERE rb.host = ra.host
			  AND (rb.path_prefix = ''
			       OR ra.path = rb.path_prefix
			       OR left(ra.path, length(rb.path_prefix) + 1) = rb.path_prefix || '/')
			ORDER BY length(rb.path_prefix) DESC
			LIMIT 1
		 ) b ON TRUE`,
		// resource_for_url("POST https://atlasisin.com/jira/t1/x")
		//   -> the resource that URL groups under, with its trust status.
		// The same match as resource_access_groups, for a raw destination
		// (auth_evidence) instead of a stored access. An empty destination
		// gives resource_id ''.
		`CREATE OR REPLACE FUNCTION resource_for_url(raw TEXT,
			OUT resource_id TEXT, OUT resource_name TEXT, OUT trust_status TEXT)
		 LANGUAGE sql STABLE AS $$
			SELECT COALESCE(b.host || b.path_prefix, p.host),
			       COALESCE(b.name, p.host),
			       COALESCE(b.trust_status, 'Unreviewed')
			FROM resource_url_parts(raw) p
			LEFT JOIN LATERAL (
				SELECT rb.host, rb.path_prefix, rb.name, rb.trust_status
				FROM resource_bases rb
				WHERE rb.host = p.host
				  AND (rb.path_prefix = ''
				       OR p.path = rb.path_prefix
				       OR left(p.path, length(rb.path_prefix) + 1) = rb.path_prefix || '/')
				ORDER BY length(rb.path_prefix) DESC
				LIMIT 1
			) b ON TRUE
		 $$`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			log.Printf("[migrate] resources: %v", err)
		}
	}

	// credentials: the status an admin gave a credential. Only credentials
	// someone has set a status on have a row; no row means active.
	conn.Exec(`CREATE TABLE IF NOT EXISTS credentials (
		credential_id TEXT PRIMARY KEY,
		status        TEXT NOT NULL DEFAULT 'active'
		              CHECK (status IN ('active', 'flagged', 'compromised')),
		reason        TEXT NOT NULL DEFAULT '',
		updated_by    TEXT NOT NULL DEFAULT '',
		updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	d := &DB{conn: conn}
	if n, err := d.BackfillResources(); err != nil {
		log.Printf("[resources] backfill FAILED: %v", err)
	} else if n > 0 {
		log.Printf("[resources] backfilled %d access record(s)", n)
	}

	return d
}

func (d *DB) Close() {
	d.conn.Close()
}
