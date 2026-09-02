package db

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type OrgMetrics struct {
	AgentCount        int
	IntentCount       int
	InteractionsCount int
	ThreatCount       int
}

type AdminRecord struct {
	DID            string
	OrganizationID string
	APIKey         string
	Email          string
	Name           string
	PasswordHash   string
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
	InteractionID       string
	From                string
	FromName            string
	To                  string
	ToName              string
	Type                string
	Direction           string
	Threat              bool
	ThreatID            string
	ThreatTitle         string
	IntentID            string
	Message             string
	Signature           string
	ProvenanceReqID     string
	ProvenanceRecordID  string
	Time                time.Time
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
	IntentID             string
	InitiatorDID         string
	InitiatorName        string
	OrgID                string
	StartedAt            time.Time
	EndedAt              *time.Time
	Status               string
	ThreatDetected       bool
	FlowType             string
	Executor             string
	ChainDepth           int
	InteractionsCount    int
	AgentsCount          int
	ToolsCount           int
	ThreatCount          int
	FirstInteractionAt   *time.Time
	LastInteractionAt    *time.Time
	RuntimeSeconds       float64
	Title                string
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
}

type UserInfoRecord struct {
	UserDID           string
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

type IntentBlockRecord struct {
	ID             string
	IntentID       string
	BlockIndex     int
	AgentDID       string
	AgentName      string
	Direction      string
	BlockType      string
	Message        string
	Response       string
	DelegateTo     string
	ReceivedFrom   string
	CbacApp        string
	CbacDecision   string
	ThreatDetected bool
	TrustIssues    []string
	Signature      string
	CreatedAt      time.Time
	FromDID        string
	FromName       string
	FromType       string
	ToDID          string
	ToName         string
	ToType         string
	RawData        json.RawMessage
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
			password        TEXT,
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
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS provenance_req_id TEXT;
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';
		ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS provenance_record_id TEXT;
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
		ALTER TABLE new_intents ADD COLUMN IF NOT EXISTS provenance_req_id TEXT;
		ALTER TABLE new_intents ADD COLUMN IF NOT EXISTS provenance_record_id TEXT;
		CREATE TABLE IF NOT EXISTS new_tools (
			did             TEXT PRIMARY KEY,
			name            TEXT,
			organization_id TEXT
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS intent_block_data (
			id             TEXT PRIMARY KEY,
			intent_id      TEXT NOT NULL,
			block_index    INTEGER,
			agent_did      TEXT DEFAULT '',
			agent_name     TEXT DEFAULT '',
			direction      TEXT DEFAULT '',
			block_type     TEXT DEFAULT '',
			message        TEXT DEFAULT '',
			response       TEXT DEFAULT '',
			delegate_to    TEXT DEFAULT '',
			received_from  TEXT DEFAULT '',
			cbac_app       TEXT DEFAULT '',
			cbac_decision  TEXT DEFAULT '',
			threat_detected INTEGER DEFAULT 0,
			trust_issues   TEXT DEFAULT '[]',
			created_at     TIMESTAMPTZ DEFAULT NOW()
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Runtime migrations for existing databases.
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS from_did  TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS from_name TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS from_type TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS to_did    TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS to_name   TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE intent_block_data ADD COLUMN IF NOT EXISTS to_type   TEXT NOT NULL DEFAULT ''`)
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE`)
	conn.Exec(`ALTER TABLE new_interactions ADD COLUMN IF NOT EXISTS message TEXT DEFAULT ''`)
	conn.Exec(`ALTER TABLE new_admins ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''`)
	conn.Exec(`ALTER TABLE new_admins ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
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
	// Migrate new_tools primary key from (did, organization_id) → did.
	conn.Exec(`DELETE FROM new_tools WHERE ctid NOT IN (SELECT MIN(ctid) FROM new_tools GROUP BY did)`)
	conn.Exec(`ALTER TABLE new_tools DROP CONSTRAINT IF EXISTS new_tools_pkey`)
	conn.Exec(`ALTER TABLE new_tools ADD PRIMARY KEY (did) `)
	conn.Exec(`ALTER TABLE new_tools ALTER COLUMN organization_id DROP NOT NULL`)
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
		(4001, 'MCP Tool Exec Error',           'The MCP tool call failed to execute')
		ON CONFLICT (code) DO NOTHING`)

	return &DB{conn: conn}
}

func (d *DB) Close() {
	d.conn.Close()
}
