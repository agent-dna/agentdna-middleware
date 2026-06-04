# AgentDNA Middleware

Middleware for the AgentDNA platform. Sits in front of a Rubix blockchain node and does two things:

1. **Proxy** — forwards all `/rubix/*` traffic to the Rubix node, and on the way intercepts NFT payloads to populate the dashboard database.
2. **Dashboard API** — JWT-protected REST endpoints that serve the AgentDNA web UI (metrics, agents, interactions, intents, tools, requests).

---

## Table of Contents

- [Quickstart](#quickstart)
- [Environment Variables](#environment-variables)
- [Authorization](#authorization)
- [Database Tables](#database-tables)
- [API Reference](#api-reference)
  - [Public Routes](#public-routes)
  - [Dashboard — JWT Protected](#dashboard--jwt-protected)
  - [Rubix Proxy & NFT Ingestion](#rubix-proxy--nft-ingestion)
- [NFT Payload Formats](#nft-payload-formats)

---

## Quickstart

```bash
# 1. Start Postgres (Docker)
docker compose up -d

# 2. Copy and fill in environment variables
cp .env.example .env

# 3. Run
go run .

# Or build a binary
go build -o agentdna-middleware . && ./agentdna-middleware
```

Health check:
```bash
curl http://localhost:9000/healthz
# {"status":"ok"}
```

Create the first admin:
```bash
curl -s -X POST http://localhost:9000/create-admin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@myorg.com","password":"secret","orgID":"Test_Org"}' | jq .
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL DSN, e.g. `postgres://agentdna:agentdna@localhost:5433/agentdna?sslmode=disable` |
| `RUBIX_NODE_URL` | Yes | Base URL of the Rubix blockchain node, e.g. `http://localhost:20000` |
| `SERVER_PORT` | Yes | Port the middleware listens on, e.g. `9000` |
| `JWT_SECRET` | Yes | Secret used to sign and verify JWT tokens |
| `AGENT_SERVICE_URL` | No | Base URL of the agent microservice |
| `CREATE_AGENT_ENDPOINT` | No | Base URL for the create-agent endpoint, e.g. `http://localhost:8001/` |
| `UPDATE_AGENT_ENDPOINT` | No | Base URL for the update-agent-policies endpoint, e.g. `http://localhost:8001/` |

Example `.env`:
```env
DATABASE_URL=postgres://agentdna:agentdna@localhost:5433/agentdna?sslmode=disable
SERVER_PORT=9000
JWT_SECRET=agentdna-dev-secret-key-2025
RUBIX_NODE_URL=http://localhost:20000
AGENT_SERVICE_URL=http://localhost:9000
CREATE_AGENT_ENDPOINT=http://localhost:8001/
UPDATE_AGENT_ENDPOINT=http://localhost:8001/
```

---

## Authorization

### JWT Auth

All dashboard routes require a Bearer token:
```
Authorization: Bearer <token>
```

Tokens are issued by `POST /login` and expire after **7 days**.

JWT payload:
```json
{
  "did":      "user or admin DID",
  "email":    "user@example.com",
  "org_id":   "Test_Org",
  "nft_id":   "user NFT ID (empty for admins)",
  "api_key":  "uuid",
  "is_admin": false
}
```

**Admin-only endpoints** return `403` if `is_admin` is `false`:
- `POST /agent-creation-request-result-submit`
- `POST /agent-info-edit`
- `GET /agent-access-requests-list-org`
- `POST /agent-access-request-submit`
- `POST /upload-agent-policy`

**Org isolation** — every query is filtered to the `org_id` in the JWT. Users cannot access data from other organizations.

---

## Database Tables

Tables are auto-created on startup with `CREATE TABLE IF NOT EXISTS`. New columns on existing databases are applied with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.

| Table | Primary Key | Purpose | 
|---|---|---|
| `new_admins` | `did` | Organization admins |
| `new_org_users` | `did` | Users within an organization |
| `new_agents` | `did` | Agents registered under an organization |
| `new_interactions` | `interaction_id` | Individual hops extracted from intent chains |
| `new_intents` | `intent_id` | Intent sessions (one intent = one chain NFT) |
| `new_tools` | `(did, organization_id)` | External tools called by agents |
| `new_requests` | `request_id` | Agent deployment and agent-access workflow requests |

### Schemas

#### `new_admins`
```sql
did             TEXT PRIMARY KEY,
organization_id TEXT,
api_key         TEXT,
email           TEXT,
password        TEXT,        -- bcrypt hash
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
name              TEXT DEFAULT '',
email             TEXT,
password          TEXT,      -- bcrypt hash, default "test123" for NFT-created users
policy            TEXT DEFAULT '',
agent_count       INTEGER DEFAULT 0,
intent_count      INTEGER DEFAULT 0,
threat_count      INTEGER DEFAULT 0,
agent_access_list TEXT DEFAULT '[]',
created_at        TIMESTAMPTZ DEFAULT NOW()
```

#### `new_agents`
```sql
did                TEXT PRIMARY KEY,
name               TEXT DEFAULT '',
deployer_did       TEXT,     -- defaults to "User_One" if missing in NFT
organization_id    TEXT,     -- defaults to "Test_Org" if missing in NFT
nft_id             TEXT,
policy             TEXT,
interactions_count INTEGER DEFAULT 0,
intent_count       INTEGER DEFAULT 0,
threat_count       INTEGER DEFAULT 0,
created_at         TIMESTAMPTZ DEFAULT NOW()
```

> Agent name defaults to `Agent_Finance_N` (where N = count of existing agents with that prefix + 1) when not present in the NFT.

#### `new_interactions`
```sql
interaction_id     TEXT PRIMARY KEY,
initiator_did      TEXT DEFAULT '',
initiator_name     TEXT DEFAULT '',
interacted_to_did  TEXT DEFAULT '',
interacted_to_name TEXT DEFAULT '',
block_type         TEXT DEFAULT '',   -- delegate | execute | tool_call | etc.
threat             INTEGER DEFAULT 0,
intent_id          TEXT DEFAULT '',
organization_id    TEXT DEFAULT '',
time               TIMESTAMPTZ DEFAULT NOW()
```

#### `new_intents`
```sql
intent_id        TEXT PRIMARY KEY,
interaction_ids  TEXT DEFAULT '[]',
initiator_did    TEXT DEFAULT '',
organization_id  TEXT DEFAULT '',
started_at       TIMESTAMPTZ DEFAULT NOW(),
ended_at         TIMESTAMPTZ,
status           TEXT DEFAULT 'running',
threat_detected  INTEGER DEFAULT 0,
flow_type        TEXT DEFAULT '',     -- simple | delegated | fan_out | cbac | retry | cosign | external_trigger
executor         TEXT DEFAULT 'user',
chain_depth      INTEGER DEFAULT 0
```

#### `new_tools`
```sql
did             TEXT PRIMARY KEY,
name            TEXT,
organization_id TEXT    -- stored for reference; org scoping is done via interactions join
```

> Tools are global (unique by `did`). When querying by org, the middleware joins through `new_interactions` to surface only tools that org's agents have called.

#### `new_requests`
```sql
request_id      TEXT PRIMARY KEY,
request_type    TEXT,    -- 'deploy_agent' | 'agent_access'
policy          TEXT,
creator_did     TEXT,
agent_did       TEXT DEFAULT '',
agent_name      TEXT DEFAULT '',
request_info    TEXT DEFAULT '',
organization_id TEXT DEFAULT '',
status          TEXT DEFAULT 'pending',  -- 'pending' | 'approved' | 'rejected'
created_at      TIMESTAMPTZ DEFAULT NOW()
```

---

## API Reference

### Standard Response Envelope

All endpoints return:
```json
{ "status": true,  "data": { ... } }
{ "status": false, "message": "error description" }
```

---

### Public Routes

#### `GET /healthz`
```json
{ "status": "ok" }
```

#### `POST /login`
**Body:**
```json
{ "email": "admin@myorg.com", "password": "secret" }
```
Tries org user first, falls back to admin. Returns a JWT token.

**Response (admin):**
```json
{
  "status": true,
  "data": {
    "token": "<jwt>", "did": "...", "email": "...",
    "org_id": "Test_Org", "api_key": "...", "is_admin": true
  }
}
```

**Response (org user):**
```json
{
  "status": true,
  "data": {
    "token": "<jwt>", "did": "...", "email": "...",
    "org_id": "Test_Org", "api_key": "...", "nft_id": "...",
    "is_admin": false, "agent_access_list": ["agent-did-1"]
  }
}
```

#### `POST /create-admin`
Registers a new org admin. Calls the agent service to provision a DID, then stores the admin in the DB.

**Body:**
```json
{ "username": "admin", "email": "admin@myorg.com", "password": "secret", "orgID": "Test_Org" }
```

**Response:**
```json
{ "status": true, "data": { "did": "...", "email": "...", "orgID": "Test_Org", "apiKey": "..." } }
```

---

### Dashboard — JWT Protected

#### `GET /home-metrics?page=<n>`
Overview metrics + top agents (5 per page, by interaction volume).

```json
{
  "status": true,
  "data": {
    "agentCount": 10, "intentCount": 42, "interactionsCount": 200, "threatCount": 3,
    "page": 1,
    "agentList": [
      { "agentName": "Agent_Finance_1", "agentID": "...", "totalInteractions": 50, "totalThreats": 1 }
    ]
  }
}
```

#### `GET /interactions-list?page=<n>`
Paginated interactions for the org (10 per page, newest first).

```json
{
  "status": true,
  "data": {
    "interactionList": [
      {
        "interactionID": "uuid", "from": "agent-did", "fromName": "Agent_Finance_1",
        "to": "tool-did", "toName": "WeatherTool", "blockType": "tool_call",
        "threat": false, "intentID": "intent-uuid", "time": "2025-01-01T00:00:00Z"
      }
    ],
    "total": 100, "page": 1, "pageSize": 10, "totalPages": 10
  }
}
```

#### `GET /intent-list?page=<n>`
Paginated list of intents for the org (10 per page).

```json
{
  "status": true,
  "data": {
    "intentsList": [
      {
        "intentID": "...", "initiatorDID": "...", "startedAt": "...",
        "status": "running", "threatDetected": false,
        "flowType": "simple", "executor": "user", "chainDepth": 2
      }
    ],
    "total": 20, "page": 1, "pageSize": 10, "totalPages": 2
  }
}
```

#### `GET /agent-metrics?bestPage=<n>&worstPage=<n>`
Top 5 and bottom 5 agents by interaction volume (independently paginated).

#### `GET /agents-list?page=<n>`
```json
{
  "status": true,
  "data": {
    "agentsList": [
      {
        "agentID": "...", "agentName": "Agent_Finance_1", "createdAt": "...",
        "deployer": "...", "policy": "...",
        "totalInteractions": 50, "totalThreats": 1, "score": 98.00
      }
    ],
    "total": 10, "page": 1, "pageSize": 10, "totalPages": 1
  }
}
```

> **Score** = `(1 - threats/interactions) × 100`. Returns `100.0` when no interactions.

#### `GET /users-list?page=<n>`
```json
{
  "status": true,
  "data": {
    "usersList": [
      {
        "userID": "...", "userName": "...", "createdAt": "...",
        "totalIntents": 15, "totalThreats": 2, "accessAgentCount": 3
      }
    ],
    "total": 5, "page": 1, "pageSize": 10, "totalPages": 1
  }
}
```

#### `GET /agent-info?agentDID=<did>`
Returns `403` if agent is not in the caller's org.

```json
{
  "status": true,
  "data": {
    "agentDID": "...", "agentName": "...", "createdAt": "...",
    "deployerDID": "...", "policy": "...", "orgID": "Test_Org",
    "totalInteractions": 50, "totalThreats": 1, "score": 98.00
  }
}
```

#### `GET /intent-info?intentID=<id>`
Returns `403` if intent is not in the caller's org. Includes all interactions.

```json
{
  "status": true,
  "data": {
    "intentID": "...", "initiatorDID": "...", "startedAt": "...",
    "status": "completed", "threatDetected": false,
    "flowType": "simple", "executor": "user", "chainDepth": 2,
    "interactions": [
      {
        "interactionID": "...", "from": "...", "fromName": "...",
        "to": "...", "toName": "...", "blockType": "delegate",
        "threat": false, "time": "..."
      }
    ]
  }
}
```

#### `GET /agent-interactions?agentDID=<did>&page=<n>`
Paginated interactions for a specific agent (10 per page). Returns `403` if not in caller's org.

#### `GET /agent-intents?agentDID=<did>&page=<n>`
Paginated intents the agent participated in (10 per page). Returns `403` if not in caller's org.

#### `GET /user-intents?page=<n>`
Paginated intents initiated by the currently logged-in user (10 per page).

#### `GET /tools-list?page=<n>`
Paginated list of tools seen by the org's agents (10 per page, ordered by interaction volume).

#### `GET /tool-info?toolDID=<did>&page=<n>`
Tool detail + paginated interactions (10 per page). Returns `404` if not found.

#### `GET /search-user`
Not yet implemented.

---

### Policy Upload / Retrieval

#### `POST /upload-user-policy`
Uploads a `.md` or `.txt` file (max 1 MB) as the logged-in user's policy.

**Form data:** `file=<file>`

#### `GET /user-policy`
Returns the logged-in user's stored policy.

#### `POST /upload-agent-policy` — Admin only
Uploads a policy for an agent. Calls the external update-agent service first.

**Form data:** `agentDID=<did>`, `file=<file>`

#### `GET /agent-policy?agentDID=<did>`
Returns the stored policy for an agent. Returns `403` if not in caller's org.

---

### Agent Creation Workflow

#### `GET /agents-creation-requests-list?page=<n>`
Lists `deploy_agent` requests for the org (10 per page).

#### `POST /agents-creation-requests-create`
Creates a new agent deployment request.
```json
{ "agentName": "NewAgent", "policy": "...", "requestInfo": "optional description" }
```

#### `POST /agents-creation-requests-edit`
Edits a pending request. Only the original creator can edit, only while status is `pending`.
```json
{ "requestID": "uuid", "agentName": "UpdatedName", "policy": "...", "requestInfo": "..." }
```

#### `POST /agent-creation-request-result-submit` — Admin only
Approves or rejects a deployment request. If `approved`, calls the external create-agent service (which returns both `agentDID` and `nft_id`), then stores the agent in the DB.
```json
{ "requestID": "uuid", "status": "approved" }
```

#### `POST /agent-info-edit` — Admin only
Updates an agent's name and policy. Calls the external update-agent service first.
```json
{ "agentDID": "...", "agentName": "UpdatedName", "policy": "..." }
```

---

### Agent Access Workflow

#### `GET /agent-access-requests-list-org?page=<n>` — Admin only
Lists `agent_access` requests for the org.

#### `GET /agent-access-requests-list-user?page=<n>`
Lists the logged-in user's own `agent_access` requests.

#### `POST /agent-access-request-submit` — Admin only
Approves or rejects an access request. If `approved`, appends the agent DID to the user's `agent_access_list`.
```json
{ "requestID": "uuid", "status": "approved" }
```

---

### Rubix Proxy & NFT Ingestion

#### `ANY /rubix/*path`
Transparent reverse proxy to `RUBIX_NODE_URL`. All methods, headers, query params, and body are forwarded.

On every `POST /rubix/*` request, the middleware checks if the body contains an NFT payload (`tokens.nft[0]`). If it does, it parses the NFT type and populates the database **before** forwarding — a DB error never blocks the proxy.

| NFT type | What happens |
|---|---|
| `user_nft` | Upserts the user into `new_org_users` with a bcrypt-hashed default password (`test123`) |
| `agent_nft` | Upserts the agent into `new_agents`. Missing fields default to: deployer=`User_One`, orgID=`Test_Org`, name=`Agent_Finance_N` |
| `intent_nft` | Walks the chain, extracts all interactions and agents, auto-creates any unknown agents/users, then stores interactions → tools → intent |

**Intent chain flow types:**

| Flow | Condition |
|---|---|
| `external_trigger` | Chain contains a `trigger` block |
| `cosign` | Chain contains an `approval` block |
| `retry` | Any `delegate`/`execute` block has an `attempts` field |
| `fan_out` | Response block has `sub_responses` |
| `delegated_cbac` | CBAC present + more than 2 outbound agent hops |
| `cbac` | CBAC present |
| `delegated` | More than 2 outbound agent hops |
| `simple` | Everything else |

---

## NFT Payload Formats

#### `user_nft`
```json
{
  "type":     "user_nft",
  "user_did": "did:rubix:...",
  "metadata": {
    "name":  "Alice",
    "email": "user@example.com",
    "orgId": "Test_Org"
  }
}
```

#### `agent_nft`
```json
{
  "type":      "agent_nft",
  "agent_did": "did:rubix:...",
  "policy":    "...",
  "agent_metadata": {
    "orgId":      "Test_Org",
    "deployer":   "User_One",
    "agent_name": "Agent_Finance_1"
  }
}
```

#### `intent_nft`
The intent NFT carries a nested chain of signed blocks. The middleware walks the chain from outermost (verify) to innermost (trigger/intent) and extracts each block pair as an interaction.

```json
{
  "type":     "intent_nft",
  "executor": "user",
  "chain": {
    "agent":     "did:rubix:outer-agent",
    "name":      "Agent_Finance_1",
    "type":      "delegate",
    "direction": "outbound",
    "envelope": {
      "parent_block": {
        "agent": "did:rubix:inner-agent",
        "name":  "Agent_Finance_2",
        "type":  "execute",
        "envelope": { "payload": {}, "parent_block": null }
      },
      "payload": {}
    },
    "verification": {
      "signature_valid": true,
      "trust_issues":    []
    }
  },
  "verification": {
    "status":      "ok",
    "trust_issues": [],
    "chain_depth": 2
  }
}
```
