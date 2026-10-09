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
	Description string
}

type TopThreatRecord struct {
	ThreatCode int
	Title      string
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
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Runtime migrations for existing databases.
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE`)
	conn.Exec(`ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS message TEXT DEFAULT ''`)
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
		// The input DID is always included, so agent/admin DIDs passed through
		// user-scoped queries behave exactly as a plain "= $1" did before.
		`CREATE OR REPLACE FUNCTION user_did_set(p_did TEXT) RETURNS SETOF TEXT
		 LANGUAGE sql STABLE AS $$
			SELECT unnest(dids) FROM user_dids WHERE dids @> ARRAY[p_did]
			UNION
			SELECT p_did
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

	// Seed known threat codes.
	conn.Exec(`INSERT INTO threat_codes (code, title, description) VALUES
		(1001, 'Whitelist Error',               'The agent is not on the whitelist'),
		(2001, 'COCA Verification Failed (Light)',    'Light COCA verification failed — the interaction did not pass the lightweight consistency check'),
		(2002, 'COCA Verification Failed (Heavy)',    'Heavy COCA verification failed — the interaction did not pass the full consistency check'),
		(2003, 'COCA Verification Failed (Boundary)','Boundary COCA verification failed — the interaction violated a policy boundary constraint'),
		(3001, 'Guard: Intended Action Empty',  'Pre-model guard failed — the intended action field is empty'),
		(3002, 'Guard: Policy Lookup Failed',   'Pre-model guard failed — could not look up the policy for this agent'),
		(3003, 'Guard: No Policy Available',    'Pre-model guard failed — no policy is available for this agent'),
		(3004, 'Guard: Policy Index Failed',    'Pre-model guard failed — policy index could not be built or loaded'),
		(3005, 'Guard: Policy No Content',      'Pre-model guard failed — the policy document has no usable content'),
		(3101, 'Check 1: Drift Deny',           'Drift check denied — the request deviates from the established baseline'),
		(3201, 'Tier 1: Gap Allow',             'Tier 1 cosine-gap check passed — action allowed'),
		(3202, 'Tier 1: Gap Deny',              'Tier 1 cosine-gap check failed — semantic distance exceeds threshold'),
		(3301, 'Tier 2: No Allowed Chunks',     'Tier 2 NLI check failed — no policy chunks were marked as allowed'),
		(3302, 'Tier 2: Entailment Allow',      'Tier 2 NLI entailment check passed — action allowed'),
		(3303, 'Tier 2: Contradiction Deny',    'Tier 2 NLI contradiction check failed — action contradicts policy'),
		(3401, 'Tier 3: No Backend',            'Tier 3 LLM backend is not configured — decision deferred'),
		(3402, 'Tier 3: LLM Error',             'Tier 3 LLM backend returned an error — decision deferred'),
		(3403, 'Tier 3: LLM Keyword Deny',      'Tier 3 LLM detected a deny keyword in the response'),
		(3404, 'Tier 3: LLM Keyword Allow',     'Tier 3 LLM detected an allow keyword in the response'),
		(3405, 'Tier 3: LLM Inconclusive',      'Tier 3 LLM response was inconclusive — decision deferred'),
		(3406, 'Tier 3: LLM Allow',             'Tier 3 LLM explicitly allowed the action'),
		(3407, 'Tier 3: LLM Deny',              'Tier 3 LLM explicitly denied the action'),
		(3408, 'Tier 3: LLM Advise',            'Tier 3 LLM returned an advisory — human review recommended'),
		(3409, 'Tier 3: LLM Malformed',         'Tier 3 LLM response was malformed and could not be parsed'),
		(4001, 'MCP Tool Exec Error',           'The MCP tool call failed to execute'),
		(9101, 'CBAC Client: No Service Configured', 'No cbac_url was passed and CBAC_URL is not set in the environment'),
		(9102, 'CBAC Client: Unrecognized Response', 'The cbac-service returned a 200 response whose body carried no decision at all'),
		(9103, 'CBAC Client: Transport Failed', 'The POST to the cbac-service raised a transport error — connection refused, timed out, or bad TLS'),
		(9104, 'CBAC Client: Verdict Without Code', 'A decision came back from the cbac-service, but with no code to key off of')
		ON CONFLICT (code) DO NOTHING`)

	// Observability page: hop lookups filter/join on these columns on every
	// request (org+time window, per-intent, per-DID-pair, per-initiator).
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_org_time ON new_interactions (organization_id, time)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_intent_id ON new_interactions (intent_id)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_interactions_from_to ON new_interactions (initiator_did, interacted_to_did)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_intents_initiator ON new_intents (initiator_did)`)

	return &DB{conn: conn}
}

func (d *DB) Close() {
	d.conn.Close()
}
