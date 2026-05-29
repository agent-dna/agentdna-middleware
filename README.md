# AgentDNA Middleware

Middleware for the AgentDNA platform. Acts as a reverse proxy in front of a Rubix blockchain node, adding authentication, rate limiting, analytics, and a dashboard API for the AgentDNA web interface.

---

## Table of Contents

- [Running the Server](#running-the-server)
- [Environment Variables](#environment-variables)
- [Authorization](#authorization)
- [Database Tables](#database-tables)
- [API Reference](#api-reference)
  - [Public Routes](#public-routes)
  - [Dashboard — JWT Protected](#dashboard--jwt-protected)
  - [Rubix Proxy](#rubix-proxy)
- [Data Structures](#data-structures)
- [Admin CLI](#admin-cli)

---

## Running the Server

```bash
# Install dependencies
go mod download

# Run
go run main.go

# Build binary
go build -o agentdna-middleware .
./agentdna-middleware
```

A `.env` file in the working directory is automatically loaded.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string, e.g. `postgres://user:pass@localhost:5432/agentdna?sslmode=disable` |
| `RUBIX_NODE_URL` | Yes | Base URL of the Rubix blockchain node to proxy, e.g. `http://localhost:20000` |
| `SERVER_PORT` | Yes | Port the server listens on, e.g. `8080` |
| `JWT_SECRET` | Yes | Secret key used to sign and verify JWT tokens |
| `AGENT_SERVICE_URL` | No | Base URL of the agent microservice. Required for agent deploy/update submit endpoints |

Example `.env`:
```env
DATABASE_URL=postgres://postgres:password@localhost:5432/agentdna?sslmode=disable
RUBIX_NODE_URL=http://localhost:20000
SERVER_PORT=8080
JWT_SECRET=your-super-secret-key
AGENT_SERVICE_URL=http://localhost:9000
```

---

## Authorization

### Legacy API Key Auth (Public routes)
Endpoints that proxy billable Rubix transactions (`/rubix/v1/tx`) require an `X-API-Key` header containing a valid API key. Keys are provisioned via `POST /admin/add-user`.

Rate limit is **100 requests per key** (configurable via `db.MaxRequests`).

### JWT Auth (Dashboard routes)
All dashboard routes require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

Tokens are issued by `POST /login` and expire after **7 days**.

The JWT payload contains:
```json
{
  "did":      "user or admin DID",
  "email":    "user@example.com",
  "org_id":   "organization identifier",
  "nft_id":   "user NFT ID (empty for admins)",
  "api_key":  "user API key",
  "is_admin": false
}
```

**Admin-only endpoints** return `403 Forbidden` if `is_admin` is `false` in the token:
- `POST /agent-creation-request-result-submit`
- `POST /agent-info-edit`
- `GET /agent-access-requests-list-org`
- `POST /agent-access-request-submit`

**Org isolation** — all dashboard data is automatically filtered to the `org_id` embedded in the JWT. Users cannot access data belonging to other organizations.

---

## Database Tables

The server auto-creates all tables on startup using `CREATE TABLE IF NOT EXISTS`. Schema migrations (new columns) are applied with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.

### Legacy Tables (original system)

| Table | Purpose |
|---|---|
| `users` | API key holders for rate-limited proxy access |
| `nfts` | Agent NFTs registered on the blockchain |
| `admin` | Legacy admin credentials (username + bcrypt hash) |
| `interaction` | Raw interaction log from the old proxy handler |
| `remote` | Registry of remote agents/tools seen in interactions |

### New Tables (dashboard system)

| Table | Primary Key | Purpose |
|---|---|---|
| `new_admins` | `did` | Organization admins with full org management rights |
| `new_org_users` | `did` | Regular org users (agents/people within an org) |
| `new_agents` | `did` | Agents registered under an organization |
| `new_tools` | `(did, organization_id)` | Tools (remote agents) seen by each org's agents |
| `new_interactions` | `interaction_id` | Individual interactions between agents and tools |
| `new_intents` | `intent_id` | Intent sessions grouping one or more interactions |
| `new_requests` | `request_id` | Agent deploy and agent-access workflow requests |

### Table Schemas

#### `new_admins`
```sql
did             TEXT PRIMARY KEY,
organization_id TEXT,
api_key         TEXT,
email           TEXT,
password        TEXT,   -- bcrypt hash
agent_count     INTEGER DEFAULT 0,
intent_count    INTEGER DEFAULT 0,
threat_count    INTEGER DEFAULT 0,
total_users     INTEGER DEFAULT 0
```

#### `new_org_users`
```sql
did               TEXT PRIMARY KEY,
organization_id   TEXT,
api_key           TEXT,
nft_id            TEXT,
email             TEXT,
password          TEXT,   -- bcrypt hash
agent_count       INTEGER DEFAULT 0,
intent_count      INTEGER DEFAULT 0,
threat_count      INTEGER DEFAULT 0,
agent_access_list TEXT[],
created_at        TIMESTAMPTZ DEFAULT NOW()
```

#### `new_agents`
```sql
did                TEXT PRIMARY KEY,
deployer_did       TEXT,
organization_id    TEXT,
nft_id             TEXT,
policy             TEXT,
interactions_count INTEGER DEFAULT 0,
intent_count       INTEGER DEFAULT 0,
threat_count       INTEGER DEFAULT 0
```

#### `new_tools`
```sql
did             TEXT,
name            TEXT,
organization_id TEXT,
PRIMARY KEY (did, organization_id)
```

#### `new_interactions`
```sql
interaction_id    TEXT PRIMARY KEY,
initiator_did     TEXT,   -- agent DID
interacted_to_did TEXT,   -- tool/remote DID
threat            BOOLEAN DEFAULT FALSE,
intent_id         TEXT,
organization_id   TEXT,
time              TIMESTAMPTZ DEFAULT NOW()
```

#### `new_intents`
```sql
intent_id       TEXT PRIMARY KEY,
interaction_ids TEXT[],
initiator_did   TEXT,   -- user DID
organization_id TEXT,
started_at      TIMESTAMPTZ DEFAULT NOW(),
ended_at        TIMESTAMPTZ,
status          TEXT DEFAULT 'running',
threat_detected BOOLEAN DEFAULT FALSE
```

#### `new_requests`
```sql
request_id      TEXT PRIMARY KEY,
request_type    TEXT,   -- 'deploy_agent' | 'agent_access'
policy          TEXT,
creator_did     TEXT,
agent_did       TEXT,
agent_name      TEXT,
request_info    TEXT,
organization_id TEXT,
status          TEXT DEFAULT 'pending',  -- 'pending' | 'approved' | 'rejected'
created_at      TIMESTAMPTZ DEFAULT NOW()
```

---

## API Reference

### Public Routes

#### `GET /healthz`
Health check.

**Response:**
```json
{ "status": "ok" }
```

---

#### `POST /login`
Authenticates an org user or org admin and returns a JWT token.

**Request body:**
```json
{
  "email":    "user@example.com",
  "password": "plaintext-password"
}
```

**Response (org user):**
```json
{
  "status": true,
  "data": {
    "token":             "<jwt>",
    "did":               "did:rubix:...",
    "email":             "user@example.com",
    "org_id":            "org-123",
    "api_key":           "...",
    "nft_id":            "...",
    "is_admin":          false,
    "agent_access_list": ["agent-did-1", "agent-did-2"]
  }
}
```

**Response (admin):**
```json
{
  "status": true,
  "data": {
    "token":    "<jwt>",
    "did":      "did:rubix:...",
    "email":    "admin@example.com",
    "org_id":   "org-123",
    "api_key":  "...",
    "is_admin": true
  }
}
```

---

#### `POST /signup`
Not yet implemented.

---

#### `POST /admin/add-user`
Provisions a new API key user. Requires HTTP Basic Auth with legacy admin credentials.

**Request body:**
```json
{ "email": "user@example.com" }
```

**Response:**
```json
{ "api_key": "generated-uuid" }
```

---

#### `GET /get-balance-credits?email=<email>`
Returns remaining API call credits for a user.

**Response:**
```json
{
  "email":          "user@example.com",
  "credit_balance": 87
}
```

---

#### `GET /interactions`
Returns all raw interactions from the legacy `interaction` table.

#### `GET /interactions/agent/:did`
Returns interactions where the agent with `did` was the host.

#### `GET /interactions/tool/:did`
Returns interactions where the tool with `did` was the remote.

#### `GET /interactions/user/:email/agents`
Returns interactions for all agents owned by the given email.

#### `GET /agents`
Returns all agents with their interaction metrics (legacy table).

#### `GET /tools`
Returns all tools with their interaction metrics (legacy table).

#### `GET /metrics`
Returns ecosystem-wide totals: `total_interactions`, `total_intrusions`, `total_agents`, `total_tools`.

#### `GET /metrics/:email`
Returns metrics scoped to a specific user's agents.

---

### Dashboard — JWT Protected

All routes below require `Authorization: Bearer <token>`.

---

#### `GET /home-metrics?page=<n>`
Overview metrics for the caller's organization. Agent list is paginated at 5 per page ordered by highest interaction volume.

**Response:**
```json
{
  "status": true,
  "data": {
    "agentCount":        10,
    "intentCount":       42,
    "interactionsCount": 200,
    "threatCount":       3,
    "page":              1,
    "agentList": [
      {
        "agentName":         "MyAgent",
        "agentID":           "did:rubix:...",
        "totalInteractions": 50,
        "totalThreats":      1
      }
    ]
  }
}
```

---

#### `GET /interactions-list?page=<n>`
Paginated list of all interactions in the caller's org (10 per page, newest first).

**Response:**
```json
{
  "status": true,
  "data": {
    "interactionList": [
      {
        "interactionID": "uuid",
        "from":          "agent-did",
        "to":            "tool-did",
        "threat":        false,
        "intentID":      "intent-uuid",
        "time":          "2025-01-01T00:00:00Z"
      }
    ],
    "total":      100,
    "page":       1,
    "pageSize":   10,
    "totalPages": 10
  }
}
```

---

#### `GET /agent-metrics?bestPage=<n>&worstPage=<n>`
Agent performance metrics for the org. Returns top 5 and bottom 5 agents by interaction volume (independently paginated).

**Response:**
```json
{
  "status": true,
  "data": {
    "agentCount":       10,
    "interactionCount": 200,
    "threatCount":      3,
    "bestPage":         1,
    "worstPage":        1,
    "pageSize":         5,
    "bestPerformingAgents":  [ { "agentName": "...", "agentID": "...", "totalInteractions": 50, "totalThreats": 0 } ],
    "worstPerformingAgents": [ { "agentName": "...", "agentID": "...", "totalInteractions": 2,  "totalThreats": 1 } ]
  }
}
```

---

#### `GET /agents-list?page=<n>`
Full paginated agent list for the org (10 per page).

**Response:**
```json
{
  "status": true,
  "data": {
    "agentsList": [
      {
        "agentID":           "did:rubix:...",
        "agentName":         "MyAgent",
        "createdAt":         "2025-01-01T00:00:00Z",
        "deployer":          "deployer-did",
        "policy":            "strict",
        "totalInteractions": 50,
        "totalThreats":      1,
        "score":             98.00
      }
    ],
    "total":      10,
    "page":       1,
    "pageSize":   10,
    "totalPages": 1
  }
}
```

> **Score** = `(1 - threats / interactions) * 100`, rounded to 2 decimal places. Returns `100.0` if no interactions.

---

#### `GET /users-list?page=<n>`
Paginated list of users in the org (10 per page).

**Response:**
```json
{
  "status": true,
  "data": {
    "usersList": [
      {
        "userID":           "did:rubix:...",
        "userName":         "user@example.com",
        "createdAt":        "2025-01-01T00:00:00Z",
        "totalIntents":     15,
        "totalThreats":     2,
        "accessAgentCount": 3
      }
    ],
    "total": 5, "page": 1, "pageSize": 10, "totalPages": 1
  }
}
```

---

#### `GET /agent-info?agentDID=<did>`
Full detail for a single agent. Returns `403` if the agent does not belong to the caller's org.

**Response:**
```json
{
  "status": true,
  "data": {
    "agentDID":          "did:rubix:...",
    "agentName":         "MyAgent",
    "createdAt":         "2025-01-01T00:00:00Z",
    "deployerDID":       "did:rubix:...",
    "policy":            "strict",
    "orgID":             "org-123",
    "totalInteractions": 50,
    "totalThreats":      1,
    "score":             98.00
  }
}
```

---

#### `GET /intent-info?intentID=<id>`
Intent detail including all its interactions (transactions). Returns `403` if the intent does not belong to the caller's org.

**Response:**
```json
{
  "status": true,
  "data": {
    "intentID":       "intent-uuid",
    "initiatorDID":   "user-did",
    "startedAt":      "2025-01-01T00:00:00Z",
    "endedAt":        "2025-01-01T00:00:05Z",
    "status":         "completed",
    "threatDetected": false,
    "interactions": [
      {
        "interactionID": "uuid",
        "from":          "agent-did",
        "to":            "tool-did",
        "threat":        false,
        "time":          "2025-01-01T00:00:01Z"
      }
    ]
  }
}
```

> `endedAt` is omitted from the response if the intent has not ended.

---

#### `GET /agent-interactions?agentDID=<did>&page=<n>`
Paginated interactions initiated by a specific agent (10 per page). Returns `403` if the agent is not in the caller's org.

**Response:**
```json
{
  "status": true,
  "data": {
    "interactionsList": [ { "interactionID": "...", "from": "...", "to": "...", "threat": false, "intentID": "...", "time": "..." } ],
    "total": 50, "page": 1, "pageSize": 10, "totalPages": 5
  }
}
```

---

#### `GET /agent-intents?agentDID=<did>&page=<n>`
Paginated list of intents that the agent participated in (10 per page). Returns `403` if the agent is not in the caller's org.

**Response:**
```json
{
  "status": true,
  "data": {
    "intentsList": [
      {
        "intentID":       "...",
        "initiatorDID":   "user-did",
        "startedAt":      "2025-01-01T00:00:00Z",
        "status":         "completed",
        "threatDetected": false
      }
    ],
    "total": 20, "page": 1, "pageSize": 10, "totalPages": 2
  }
}
```

---

#### `GET /user-intents?page=<n>`
Paginated list of intents initiated by the currently logged-in user (10 per page).

**Response:** Same shape as `/agent-intents`.

---

#### `GET /tools-list?page=<n>`
Paginated list of tools (remote agents) that the org's agents have interacted with (10 per page, ordered by interaction volume).

**Response:**
```json
{
  "status": true,
  "data": {
    "toolsList": [
      {
        "toolDID":           "did:rubix:...",
        "toolName":          "WeatherTool",
        "totalInteractions": 30,
        "totalThreats":      0,
        "score":             100.00
      }
    ],
    "total": 8, "page": 1, "pageSize": 10, "totalPages": 1
  }
}
```

---

#### `GET /tool-info?toolDID=<did>&page=<n>`
Full info for a tool, scoped to the caller's org. Returns `404` if not found. Interactions paginated at 10 per page.

**Response:**
```json
{
  "status": true,
  "data": {
    "toolDID":           "did:rubix:...",
    "toolName":          "WeatherTool",
    "totalInteractions": 30,
    "totalThreats":      0,
    "score":             100.00,
    "interactions": [
      {
        "interactionID": "...",
        "from":          "agent-did",
        "threat":        false,
        "intentID":      "...",
        "time":          "..."
      }
    ],
    "total": 30, "page": 1, "pageSize": 10, "totalPages": 3
  }
}
```

---

#### `GET /search-user`
Not yet implemented.

---

### Agent Creation Request Workflow

#### `GET /agents-creation-requests-list?page=<n>`
Lists all `deploy_agent` requests for the caller's org (10 per page, any role).

**Response:**
```json
{
  "status": true,
  "data": {
    "requestsList": [
      {
        "requestID":   "uuid",
        "requestType": "deploy_agent",
        "policy":      "strict",
        "creatorDID":  "did:rubix:...",
        "agentDID":    "",
        "agentName":   "NewAgent",
        "requestInfo": "additional context",
        "status":      "pending",
        "createdAt":   "2025-01-01T00:00:00Z"
      }
    ],
    "total": 5, "page": 1, "pageSize": 10, "totalPages": 1
  }
}
```

---

#### `POST /agents-creation-requests-create`
Creates a new agent deployment request.

**Request body:**
```json
{
  "agentName":   "NewAgent",
  "policy":      "strict",
  "requestInfo": "optional description"
}
```

**Response:**
```json
{ "status": true, "data": { "requestID": "uuid" } }
```

---

#### `POST /agents-creation-requests-edit`
Edits a pending deployment request. Only the original creator can edit. Only `pending` requests can be modified.

**Request body:**
```json
{
  "requestID":   "uuid",
  "agentName":   "UpdatedName",
  "policy":      "relaxed",
  "requestInfo": "updated context"
}
```

**Response:**
```json
{ "status": true, "data": { "requestID": "uuid" } }
```

---

#### `POST /agent-creation-request-result-submit` — Admin only
Approves or rejects a deployment request. If `approved`, calls `POST <AGENT_SERVICE_URL>/deploy-agent` with the request data. The DB status is only updated if the microservice responds `200`.

**Request body:**
```json
{
  "requestID": "uuid",
  "status":    "approved"
}
```

> `status` must be `"approved"` or `"rejected"`.

**Response:**
```json
{ "status": true, "data": { "requestID": "uuid", "status": "approved" } }
```

---

#### `POST /agent-info-edit` — Admin only
Updates an agent's name and policy. Calls `POST <AGENT_SERVICE_URL>/update-agent` first. DB is only updated if the microservice responds `200`.

**Request body:**
```json
{
  "agentDID":  "did:rubix:...",
  "agentName": "UpdatedName",
  "policy":    "relaxed"
}
```

**Response:**
```json
{ "status": true, "data": { "agentDID": "did:rubix:..." } }
```

---

### Agent Access Request Workflow

#### `GET /agent-access-requests-list-org?page=<n>` — Admin only
Lists all `agent_access` requests for the org (10 per page).

**Response:** Same shape as `/agents-creation-requests-list` with `requestType: "agent_access"`.

---

#### `GET /agent-access-requests-list-user?page=<n>`
Lists the logged-in user's own `agent_access` requests (10 per page).

**Response:** Same shape as above.

---

#### `POST /agent-access-request-submit` — Admin only
Approves or rejects an agent-access request. If `approved`, the agent DID is appended to the requesting user's `agent_access_list` (deduped).

**Request body:**
```json
{
  "requestID": "uuid",
  "status":    "approved"
}
```

**Response:**
```json
{ "status": true, "data": { "requestID": "uuid", "status": "approved" } }
```

---

### Rubix Proxy

#### `ANY /rubix/*path`
Transparent reverse proxy to the configured `RUBIX_NODE_URL`. All request headers, query params, and body are forwarded as-is.

For billable paths (`/rubix/v1/tx`), a valid `X-API-Key` is required and the request count is incremented atomically.

When a transaction payload contains an NFT in `tokens.nft[0].data`, the middleware inspects the NFT type and populates the dashboard tables before forwarding:

| NFT Type | Action |
|---|---|
| `user_nft` | Registers the user DID in `new_org_users` |
| `agent_nft` | Registers the agent in `new_agents` + `nfts` |
| `intent_nft` | Records all interactions in `new_interactions`, the intent in `new_intents`, and tools in `new_tools` |

---

## Data Structures

### NFT Payload Types (parsed from blockchain transactions)

#### `user_nft`
```json
{
  "type":     "user_nft",
  "user_did": "did:rubix:...",
  "metadata": {
    "email":           "user@example.com",
    "orgId":           "org-123",
    "agentAccessList": []
  }
}
```

#### `agent_nft`
```json
{
  "type":      "agent_nft",
  "agent_did": "did:rubix:...",
  "policy":    "strict",
  "agent_metadata": {
    "orgId":     "org-123",
    "deployer":  "did:rubix:...",
    "agent_name": "MyAgent"
  }
}
```

#### `intent_nft`
```json
{
  "type": "intent_nft",
  "did":  "intent-uuid",
  "user": { "agent": "user-did", "envelope": {}, "signature": "..." },
  "host": { "agent": "host-agent-did", "envelope": {}, "signature": "..." },
  "responses": [
    { "agent": "ToolName", "agent_did": "tool-did", "envelope": {}, "signature": "..." }
  ],
  "verification": {
    "status":      "verified",
    "trust_issues": [],
    "chain_depth": 1
  },
  "cbac": { "decision": "allow", "n_denied": 0 }
}
```

### JWT Claims
```json
{
  "did":      "string",
  "email":    "string",
  "org_id":   "string",
  "nft_id":   "string",
  "api_key":  "string",
  "is_admin": false,
  "exp":      1234567890,
  "iat":      1234567890
}
```

### Standard API Response Envelope
All endpoints return:
```json
{
  "status":  true,
  "data":    { },
  "message": ""
}
```
On error, `status` is `false`, `data` is `null`, and `message` contains the error description.

---

## Admin CLI

Register an organization admin into `new_admins` directly (bypasses the API):

```bash
go run ./cmd/regadmin <DATABASE_URL> <email> <password>
```

Example:
```bash
go run ./cmd/regadmin "postgres://postgres:pass@localhost:5432/agentdna?sslmode=disable" admin@myorg.com secretpassword
```

The password is bcrypt-hashed before storage. The admin can then log in via `POST /login`.
