package db

import "time"

type Admin struct {
	DID             string `json:"id" db:"did"`
	OrganizationID  string `json:"organizationID" db:"organization_id"`
	Email          string `json:"email" db:"email"`
	Password       string `json:"password" db:"password"`
	AgentCount     int    `json:"agentCount" db:"agent_count"`
	IntentCount    int    `json:"intentCount" db:"intent_count"`
	ThreatCount    int    `json:"threatCount" db:"threat_count"`
	TotalUsers     int    `json:"totalUsers" db:"total_users"`
}

type User struct {
	DID             string   `json:"id" db:"did"`
	OrganizationID  string   `json:"organizationID" db:"organization_id"`
	Email          string   `json:"email" db:"email"`
	Password        string   `json:"password" db:"password"`
	AgentCount      int      `json:"agentCount" db:"agent_count"`
	IntentCount     int      `json:"intentCount" db:"intent_count"`
	ThreatCount     int      `json:"threatCount" db:"threat_count"`
	AgentAccessList []string `json:"agentAccessList" db:"agent_access_list"`
}

type Agent struct {
	DID                string `json:"id" db:"did"`
	DeployerDID        string `json:"deployerDID" db:"deployer_did"`
	OrganizationID    string `json:"organizationID" db:"organization_id"`
	Policy            string `json:"policy" db:"policy"`
	InteractionsCount int    `json:"interactionsCount" db:"interactions_count"`
	IntentCount       int    `json:"intentCount" db:"intent_count"`
	ThreatCount       int    `json:"threatCount" db:"threat_count"`
}

type RequestType string

const (
	RequestTypeDeployAgent RequestType = "deploy_agent"
	RequestTypeAccessAgent RequestType = "access_agent"
)

type RequestStatus string

const (
	RequestStatusApproved RequestStatus = "approved"
	RequestStatusDenied   RequestStatus = "denied"
	RequestStatusPending  RequestStatus = "pending"
)

type Request struct {
	RequestID   string        `json:"requestID" db:"request_id"`
	RequestType RequestType   `json:"requestType" db:"request_type"`
	Policy      string        `json:"policy" db:"policy"`
	CreatorDID  string        `json:"creatorDID" db:"creator_did"`
	AgentDID    *string        `json:"agentDID" db:"agent_did"`
	Status      RequestStatus `json:"status" db:"status"`
}

type Interaction struct {
	InteractionID  string    `json:"interactionID" db:"interaction_id"`
	InitiatorDID   string    `json:"initiatorDID" db:"initiator_did"`
	InteractedToDID string    `json:"interactedToDID" db:"interacted_to_did"`
	Threat         bool      `json:"threat" db:"threat"`
	IntentID       string    `json:"intentID" db:"intent_id"`
	Time           time.Time `json:"time" db:"time"`
}

type IntentStatus string

const (
	IntentStatusRunning   IntentStatus = "running"
	IntentStatusCompleted IntentStatus = "completed"
)

type Intent struct {
	InteractionIDs  []string     `json:"interactionIDs" db:"interaction_ids"`
	InitiatorDID     string       `json:"initiatorDID" db:"initiator_did"`
	StartedAt       time.Time    `json:"startedAt" db:"started_at"`
	EndedAt         *time.Time    `json:"endedAt" db:"ended_at"`
	Status          IntentStatus `json:"status" db:"status"`
	ThreatDetected  bool         `json:"threatDetected" db:"threat_detected"`
}
