# AgentDNA Dashboard — Backend Data Inventory

What's already shown to the frontend, and backend data that's fetched but dropped before the JSON response.

Scope: all `GET /dashboard/v1/*` endpoints (`router/router.go`, `handler/handler.go`).

---

## 1. Home / Overview

**GET /home-metrics** — `HomeMetrics`
Landing-page KPI summary (org-wide for admins, own-scope for users).
- `agentCount, intentCount, interactionsCount, threatCount`
- `agentCount24hChange, intentCount24hChange, interactionsCount24hChange, threatCount24hChange`
- `agentList[]` (top 5): `agentName, agentID, totalInteractions, totalThreats`
- `flowEnabled` (derived boolean)

**GET /agent-metrics** — `AgentMetrics`
Best / worst performing agents leaderboard.
- `agentCount, interactionCount, threatCount`
- `bestPerformingAgents[]` / `worstPerformingAgents[]`: `agentName, agentID, totalInteractions, totalThreats`
- `bestPage, worstPage, pageSize`

**GET /agents-apps-metrics** — `AgentsAppsMetrics`
Combined agents + apps overview widget.
- `topAgents[]`: `name, totalInteractions, totalThreats`
- `topApps[]`: `name, totalInteractions, totalThreats`
- `metrics`: `totalInteractions, totalThreats, totalAgents, totalApps, avgReliability`

**GET /interactions/series?range=24h|7d** — `InteractionSeries`
Time-bucketed chart series of safe vs. threat interaction volume.
- `safe[]` (int array), `threats[]` (int array) — parallel bucketed arrays

**GET /global-stats** (public, no auth) — `GlobalStats`
Platform-wide totals across all organizations.
- `totalUsers, totalAgents, totalInteractions, totalIntents, totalThreats`

---

## 2. Profile

**GET /user-profile** — `UserProfile`
Logged-in org user's own profile.
- `name, email, apiKey, organizationID, createdAt, adminEmail`

**GET /admin-profile** — `AdminProfile`
Logged-in admin's own profile + org counters.
- `name, email, organizationID, apiKey, agentCount, intentCount, threatCount, totalUsers, createdAt`

---

## 3. Agents

**GET /agents-list** — `AgentsList`
Paginated agent roster (admin: org-wide, user: own agents).
- `agentsList[]`: `agentID, agentName, createdAt, deployer, policy, totalInteractions, totalThreats, score`
- `total, page, pageSize, totalPages`
- ⚠ does **not** include `revoked` status (see Gaps, item 4)

**GET /agent-info?agentDID=** — `AgentInfo`
Single-agent detail panel.
- `agentDID, agentName, createdAt, deployerDID, deployerName, policy, orgID`
- `totalInteractions, totalThreats, score, revoked`
- `appsInteracted` (count), `appsList[]` (tool names/DIDs contacted)

**GET /agent-interactions?agentDID=** — `AgentInteractions`
Paginated interaction log for one agent.
- `interactionsList[]`: `interactionID, from, fromName, to, toName, type, direction, threat, threatID, intentID, time, message`
- `total, page, pageSize, totalPages`

**GET /agent-intents?agentDID=** — `AgentIntents`
Paginated intents initiated by / involving one agent (shared `buildIntentList` — see Section 5 for full field list).

**GET /agent-lhi-scores?agentDID=** — `AgentLHIScores`
Proxies cbac-service; agent's trust-edge scores per callee.
- `agentDID, scores[]`: `callee_name, callee_type, mcp_did, intent_score, policy_score, hallucination_score, trust, created_at`

**GET /tool-agent-scores?toolDID=** — `ToolAgentScores`
LHI scores of every agent that has contacted a given tool.
- `toolDID, toolName, agents[]`: `agentDID, agentName, intentScore, policyScore, hallucinationScore, trust`

**GET /agents-creation-requests-list[-user]** — `AgentsCreationRequestsList[User]`
Pending/approved "create agent" requests queue.
- `requestsList[]`: `requestID, requestType, policy, creatorDID, agentDID, agentName, requestInfo, status, createdAt`
- `total, page, pageSize, totalPages`

**GET /agent-access-requests-list-org / -list-user** — `AgentAccessRequestsListOrg/User`
Same shape as creation requests (shared `buildRequestList`), for `agent_access` request type.

**GET /agent-policy?agentDID=** — `GetAgentPolicy`
Current policy document text for an agent.
- `agentDID, policy` (raw text)

**GET /agent-policy-history?agentDID=** — `GetAgentPolicyHistory`
On-chain policy update history.
- `agentDID, nftID, history[]`: `updateID, time` (epoch)

**GET /agent-policy-update?agentDID=&updateID=** — `GetAgentPolicyUpdate`
Full decoded policy text for one historical update.
- `updateID, time, policy` (decoded text)

---

## 4. Users

**GET /users-list** — `UsersList`
Paginated org user roster (admin view).
- `usersList[]`: `userID, userName, createdAt, totalIntents, totalThreats, accessAgentCount`
- `total, page, pageSize, totalPages`

**GET /user-info?userID=** — `UserInfo`
Single-user detail page with nested paginated sub-resources.
- `user`: `userID, userName, displayName, createdAt, lastActive, isActive, accessAgentCount, totalInteractions, totalThreats, totalIntents, totalAgentsDeployed`
- `interactions.list[]`: `interactionID, from, fromName, to, toName, type, threat, threatID, intentID, message, signature, provenanceRecordID, time` (+ pagination)
- `intents.list[]`: full intent fields, see `buildIntentList` (+ pagination)
- `threats.list[]`: `interactionID, from, fromName, to, toName, type, threat, intentID, message, signature, provenanceRecordID, time` (+ pagination)
- `agents.list[]`: `agentDID, agentName, status` (derived), `created` (epoch), `totalInteractions, totalThreats` (+ pagination)

**GET /user-intents** — `UserIntents`
Paginated intents initiated by the logged-in user (`buildIntentList` shape).

**GET /user-policy** — `GetUserPolicy`
Logged-in user's own policy document.
- `policy` (raw text)

---

## 5. Intents

**GET /intent-list** — `IntentList`
Paginated intent list (admin: org-wide, user: own). Shared `buildIntentList`.
- Per intent: `intentID, title` (truncated to 5 words), `initiatorDID, initiatorName, startedAt, status, reviewStatus, threatDetected, flowType, executor, chainDepth, interactionsCount, agentsCount, toolsCount, threatCount, firstInteractionAt, lastInteractionAt, runtimeSeconds, endedAt` (if set)
- `total, page, pageSize, totalPages`

**GET /intent-info?intentID=** — `IntentInfo`
Single-intent detail with full interaction transcript.
- `intentID, initiatorDID, initiatorName, startedAt, status, reviewStatus, threatDetected, flowType, executor, chainDepth, interactionsCount, agentsCount, toolsCount, firstInteractionAt, lastInteractionAt, runtimeSeconds, provenanceRecordID, endedAt` (if set)
- `interactions[]`: `interactionID, from, fromName, to, toName, type, direction, threat, threatID, time, message, signature, provenanceReqID, provenanceRecordID`

**GET /intent-diagram?intentID=** — `IntentDiagram`
Flow-diagram view of one intent.
- `basicInfo`: `intentID, initiatorDID, initiatorName, flowType, status, threatDetected, chainDepth, interactionsCount, agentsCount, toolsCount, startedAt` — ⚠ drops `reviewStatus` & `executor` (see Gaps, item 6)
- `interactions[]`: `interactionID, initiator, initiatorName, to, toName, type, message, intentID, threat, threatID, epoch, signature, provenanceReqID, provenanceRecordID`

**GET /intent-block-data?intent_id=** — `GetIntentBlockData`
Nested block-chain structure for one intent — agent hop-by-hop trace.
- Per block: `id, block_index, block_type, from{did,name,type}, to{did,name,type}, message, signature, threat_detected, trust_issues[], created_at, parent_block` (recursive)
- ⚠ drops `response, delegate_to, received_from, cbac_app, cbac_decision` (see Gaps, item 2)

**GET /intent-raw-data?intent_id=** — `GetIntentRawData`
Raw JSON payload per block, for debugging/inspection.
- `[]{ block_index, raw_data }` — opaque JSON blob per block

---

## 6. Interactions

**GET /interactions-list** — `InteractionsList`
Paginated global interaction feed (org/user scoped, optional `intentID` filter).
- `interactionList[]`: `interactionID, from, fromName, to, toName, type, direction, threat, threatID, intentID, time, message`
- `total, page, pageSize, totalPages`
- ⚠ `threat` is a bare bool — resolved `threatCode`/`threatTitle` not included (see Gaps, notes)

---

## 7. Threats

**GET /threats-list** — `ThreatsList`
Paginated threat-flagged interactions (org/user scoped).
- `threatsList[]`: `interactionID, from, fromName, to, toName, type, direction, threat, threatID, threatCode, threatTitle, intentID, reviewStatus, time, message`
- `total, page, pageSize, totalPages`

**GET /threat-events** — `ThreatEvents`
Paginated raw threat log (from `threats` table).
- `threats[]`: `id, intent_id, interaction_id, time, threat_code, message`
- `total, page, limit`

**GET /threat-by-id?threat_id=** — `ThreatByID`
Single threat record + resolved code metadata.
- `id, intent_id, interaction_id, time, threat_code, message, title, description`

**GET /threat-detail?threat_code=** — `ThreatDetail`
All occurrences of a given threat code.
- `threat_code, title, description, count, threats[]`: `id, intent_id, interaction_id, time, message`

**GET /top-threats** — `TopThreats`
Top 5 threat codes by frequency (chart/leaderboard).
- `[]{ threat_code, title, count }` — array is the top-level data payload

**GET /top-threat-agents** — `TopThreatAgents`
Paginated leaderboard of agents ranked by threat count.
- `agentsList[]`: `agentDID, agentName, totalInteractions, totalThreats`
- `total, page, pageSize, totalPages`

---

## 8. Tools / Apps

**GET /tools-list** — `ToolsList`
Paginated tool/app roster.
- `toolsList[]`: `toolDID, toolName, totalInteractions, totalThreats, totalIntents, score`
- `total, page, pageSize, totalPages`
- ⚠ `lastInteractedAt` fetched by `ToolInfo` but not by this list query (see Gaps, item 3)

**GET /tool-info?toolDID=|name=** — `ToolInfo`
Single-tool detail with nested paginated sub-resources.
- `toolDID, toolName, totalInteractions, totalThreats, totalIntents, totalAgents, score, lastInteractedAt`
- `interactions.list[]`: same interaction fields as elsewhere (+ pagination)
- `intents.list[]`: full intent fields via `buildIntentList` (+ pagination)

---

## 9. Search

**GET /search?q=** — `Search`
Global search across agents / apps / intents.
- `agents[]`: `did, name, orgID`
- `apps[]`: `did, name`
- `intents[]`: `intentID, flowType, status, threatDetected, startedAt`

---

## Backend Data Fetched, But Not Shown on the Frontend

These are fields the database queries already fetch into a Go struct, but that get dropped before the handler builds its JSON response. Each is a candidate to surface with **no new query needed** — just a field added to the response.

**1. Agent NFT ID never shown on leaderboards**
`AgentVolumeRecord.AgentNFTID` is fetched by `GetTopAgentsByOrg` / `GetTopAgentsByUser` / `GetBottomAgentsByOrg` / `GetTopThreatAgentsByOrg` (`db/service.go`), but every consumer (`HomeMetrics` agentList, `AgentMetrics` best/worst lists, `TopThreatAgents`) drops it before the JSON is built.

**2. CBAC decision & delegation hidden in the block-diagram view**
`GetIntentBlocksByIntent` (`db/service.go`) fetches `Response`, `DelegateTo`, `ReceivedFrom`, `CbacApp` and `CbacDecision` per block, but `GetIntentBlockData` (`handler.go`) never copies them into `blockOut`. The allow/deny decision and which app/agent a step delegated to is only visible via the separate, unstructured `/intent-raw-data` endpoint.

**3. Tools list has no "last active" column**
`GetToolsByOrg` (used by `ToolsList`) only scans `did, name, total_interactions, total_threats, total_intents, score` — it never selects `last_interacted_at`, even though `GetToolByNameOrDID` (used by `ToolInfo`) does. The tools table can't show recency without an extra per-row call.

**4. Agents list has no revoked status**
`GetAgentInfo` (single-agent) surfaces `revoked`, but `GetAgentsByOrg` / `GetAgentsByUser` (used by the paginated `AgentsList` table) don't select `new_agents.revoked` at all — the grid can't flag a revoked agent inline.

**5. Full intent title is never returned**
`IntentRecord.Title` is always truncated to 5 words by `firstNWords()` in `buildIntentList`. No list or detail endpoint returns the untruncated title, even though it's in the DB record.

**6. Intent diagram drops reviewStatus and executor**
`GetIntentInfo` fetches `ReviewStatus` and `Executor` (and `IntentInfo` returns both), but `IntentDiagram`'s `basicInfo` omits both — so the human-triage state (Ongoing / Acknowledged / Flagged) isn't visible on the diagram view.

**7. Request queues never expose orgID**
`buildRequestList` (shared by creation-requests and access-requests endpoints) never includes `orgID` in its rows, though the underlying query is org-scoped.

**8. Per-tool LHI scores have no timestamp**
`ToolAgentScores` copies only `IntentScore` / `PolicyScore` / `HallucinationScore` / `Trust` from each `LHIScoreEntry`, discarding `CreatedAt` — so the per-tool score view can't show when a score was last computed (`AgentLHIScores`, by contrast, returns the whole entry including `CreatedAt`).

**9. AgentMetrics drops the 24h-change deltas**
`GetOrgMetrics` returns `AgentCount24hChange` / `IntentCount24hChange` / `InteractionsCount24hChange` / `ThreatCount24hChange`. `HomeMetrics` surfaces all four; `AgentMetrics` calls the same struct but only reads `AgentCount` / `InteractionsCount` / `ThreatCount`, silently dropping the deltas.

### Additional scope notes

- Threat context requires a second call: plain interaction lists (`InteractionsList`, `AgentInteractions`, and the interaction sub-lists on `UserInfo`/`ToolInfo`) only return `threat` (bool) and `threatID` — the resolved `threatCode`/`threatTitle` join used by `ThreatsList` is never applied there, so the UI needs a follow-up `/threat-by-id` call to explain why something was flagged.
- No endpoint returns `new_agents.nft_id` directly — it's used internally by `agent-policy-history`'s on-chain lookup but never returned in the response.

---

Key files: `handler/handler.go` (all handlers) · `router/router.go` (route registration) · `db/db.go` (struct defs) · `db/service.go` (query implementations)
