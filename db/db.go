package db

import (
	"database/sql"
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
	InteractionID string
	From          string
	FromName      string
	To            string
	ToName        string
	BlockType     string
	Threat        bool
	IntentID      string
	Time          time.Time
}

type IntentRecord struct {
	IntentID       string
	InitiatorDID   string
	OrgID          string
	StartedAt      time.Time
	EndedAt        *time.Time
	Status         string
	ThreatDetected bool
	FlowType       string
	Executor       string
	ChainDepth     int
}

type ToolRecord struct {
	DID               string
	Name              string
	TotalInteractions int
	TotalThreats      int
	TotalIntents      int
	Score             float64
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
	Email           string
	PasswordHash    string
	Policy          string
	AgentCount      int
	IntentCount     int
	ThreatCount     int
	AgentAccessList []string
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
			did               TEXT PRIMARY KEY,
			organization_id   TEXT,
			api_key           TEXT,
			nft_id            TEXT,
			email             TEXT,
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
			block_type        TEXT DEFAULT '',
			threat            INTEGER DEFAULT 0,
			intent_id         TEXT DEFAULT '',
			organization_id   TEXT DEFAULT '',
			time              TIMESTAMPTZ DEFAULT NOW()
		);
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
		CREATE TABLE IF NOT EXISTS new_tools (
			did             TEXT,
			name            TEXT,
			organization_id TEXT,
			PRIMARY KEY (did, organization_id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Runtime migration: add created_at column to new_agents for existing databases.
	conn.Exec(`ALTER TABLE new_agents ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)

	return &DB{conn: conn}
}

func (d *DB) Close() {
	d.conn.Close()
}
