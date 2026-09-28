package handler

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"

	"github.com/gin-gonic/gin"
)

// obsFlaggedCodes / obsElevatedCodes classify a hop's threat code into the
// Observability page's outcome buckets. Codes not listed here (including the
// "Allow" tier-check codes 3201/3302/3404/3406, which are stored as
// threat=1 rows by a pre-existing flagging bug) fall through to "allowed".
var obsFlaggedCodes = map[int]bool{
	1001: true,
	2001: true, 2002: true, 2003: true,
	3001: true, 3002: true, 3003: true, 3004: true, 3005: true,
	3101: true, 3202: true, 3301: true, 3303: true, 3403: true, 3407: true,
}

var obsElevatedCodes = map[int]bool{
	3401: true, 3402: true, 3405: true, 3408: true, 3409: true,
	9101: true, 9102: true, 9103: true, 9104: true,
}

var obsOutcomeRank = map[string]int{"allowed": 0, "elevated": 1, "flagged": 2}

func obsHopOutcome(threat bool, code int) string {
	if threat && obsFlaggedCodes[code] {
		return "flagged"
	}
	if threat && obsElevatedCodes[code] {
		return "elevated"
	}
	return "allowed"
}

func obsWorseOutcome(a, b string) string {
	if obsOutcomeRank[b] > obsOutcomeRank[a] {
		return b
	}
	return a
}

func obsCocaResult(code int) string {
	if code == 2001 || code == 2002 || code == 2003 {
		return "fail"
	}
	return "pass"
}

func obsWhitelistResult(code int) string {
	if code == 1001 {
		return "fail"
	}
	return "pass"
}

// obsHopKind classifies a hop by registry membership, never by DID prefix.
func obsHopKind(from, to string, users map[string]*db.ObsUser, agents map[string]*db.ObsAgent, apps map[string]*db.ObsApp) string {
	if _, ok := users[from]; ok {
		if _, ok := agents[to]; ok {
			return "user_agent"
		}
	}
	if _, ok := agents[from]; ok {
		if _, ok := apps[to]; ok {
			return "agent_app"
		}
		if _, ok := agents[to]; ok && to != from {
			return "agent_agent"
		}
	}
	return ""
}

// obsParseRange returns the normalized range label (defaulting to 24h on any
// unrecognized value) and its cutoff time.
func obsParseRange(c *gin.Context) (string, time.Time) {
	r := c.DefaultQuery("range", "24h")
	if r == "all" {
		// No lower bound — every interaction ever recorded. time.Time{} (year 1)
		// sorts before any real interaction timestamp.
		return "all", time.Time{}
	}
	var d time.Duration
	switch r {
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		r = "24h"
		d = 24 * time.Hour
	}
	return r, time.Now().Add(-d)
}

// obsParseStatus returns "all", "risk" or "flagged" (defaulting to "all").
func obsParseStatus(c *gin.Context) string {
	s := c.DefaultQuery("status", "all")
	if s != "risk" && s != "flagged" {
		return "all"
	}
	return s
}

func obsPassesStatus(status, outcome string) bool {
	switch status {
	case "flagged":
		return outcome == "flagged"
	case "risk":
		return outcome == "flagged" || outcome == "elevated"
	default:
		return true
	}
}

func obsPagination(c *gin.Context, defaultPageSize int) (page, pageSize int) {
	page = 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	pageSize = defaultPageSize
	if ps, err := strconv.Atoi(c.Query("pageSize")); err == nil && ps > 0 {
		pageSize = ps
	}
	return page, pageSize
}

func obsSlicePage[T any](items []T, page, pageSize int) []T {
	total := len(items)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return items[start:end]
}

// obsScope resolves org/admin/DID context common to every observability
// endpoint. Writes the error response itself and returns ok=false if the org
// context is missing.
func (h *Handler) obsScope(c *gin.Context) (orgID string, isAdmin bool, callerDID string, ok bool) {
	orgID = c.GetString(CtxOrgID)
	if orgID == "" {
		log.Printf("[observability] path=%s rejected — missing org context", c.Request.URL.Path)
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return "", false, "", false
	}
	isAdmin, callerDID = c.GetBool(CtxIsAdmin), c.GetString(CtxDID)
	log.Printf("[observability] path=%s query=%q orgID=%q isAdmin=%v callerDID=%q",
		c.Request.URL.Path, c.Request.URL.RawQuery, orgID, isAdmin, callerDID)
	return orgID, isAdmin, callerDID, true
}

// obsHopPolicy returns "<code> · <title>" for a flagged/elevated hop, or nil
// for an allowed one.
func obsHopPolicy(h *db.ObsHop) *string {
	if obsHopOutcome(h.Threat, h.Code) == "allowed" {
		return nil
	}
	s := fmt.Sprintf("%d · %s", h.Code, h.Title)
	return &s
}

// obsWorstPolicy returns the policy string for the worst-outcome hop across
// the slice, or nil if none are flagged/elevated.
func obsWorstPolicy(hops []*db.ObsHop) *string {
	var best *string
	bestRank := -1
	for _, hop := range hops {
		outcome := obsHopOutcome(hop.Threat, hop.Code)
		rank := obsOutcomeRank[outcome]
		if rank > 0 && rank > bestRank {
			bestRank = rank
			s := fmt.Sprintf("%d · %s", hop.Code, hop.Title)
			best = &s
		}
	}
	return best
}

// obsContext is the scoped, range/status-filtered hop set plus the org
// registries, loaded once per request and shared across an endpoint's
// aggregation logic.
type obsContext struct {
	orgID           string
	users           map[string]*db.ObsUser
	agents          map[string]*db.ObsAgent
	apps            map[string]*db.ObsApp
	userAgentHops   []*db.ObsHop
	agentAppHops    []*db.ObsHop
	agentAgentHops  []*db.ObsHop
	intentInitiator map[string]string // intent_id -> initiator_did, for every intent touched by the hops above
}

// loadObsContext fetches hops for the org (scoped to scopeInitiatorDID when
// non-empty — the non-admin case), classifies each by registry lookup, drops
// anything that doesn't pass the status filter or classify as
// user_agent/agent_app, and resolves the intent-initiator map needed to
// attribute agent->app hops back to a user.
func (h *Handler) loadObsContext(c *gin.Context, scopeInitiatorDID string) (*obsContext, error) {
	orgID := c.GetString(CtxOrgID)
	rangeLabel, since := obsParseRange(c)
	status := obsParseStatus(c)

	hops, err := h.db.GetObservabilityHops(orgID, since, scopeInitiatorDID)
	if err != nil {
		return nil, fmt.Errorf("fetch hops: %w", err)
	}
	users, err := h.db.GetOrgUserRegistry(orgID)
	if err != nil {
		return nil, fmt.Errorf("fetch user registry: %w", err)
	}
	agents, err := h.db.GetOrgAgentRegistry(orgID)
	if err != nil {
		return nil, fmt.Errorf("fetch agent registry: %w", err)
	}
	apps, err := h.db.GetOrgAppRegistry(orgID)
	if err != nil {
		return nil, fmt.Errorf("fetch app registry: %w", err)
	}
	log.Printf("[observability] path=%s orgID=%q scopeInitiatorDID=%q range=%s(since=%s) status=%s rawHops=%d registrySizes(users=%d,agents=%d,apps=%d)",
		c.Request.URL.Path, orgID, scopeInitiatorDID, rangeLabel, since.UTC().Format(time.RFC3339), status,
		len(hops), len(users), len(agents), len(apps))

	octx := &obsContext{orgID: orgID, users: users, agents: agents, apps: apps}
	intentIDSet := map[string]bool{}
	ignoredCount := 0
	statusFilteredCount := 0
	for _, hop := range hops {
		outcome := obsHopOutcome(hop.Threat, hop.Code)
		if !obsPassesStatus(status, outcome) {
			statusFilteredCount++
			continue
		}
		switch obsHopKind(hop.From, hop.To, users, agents, apps) {
		case "user_agent":
			octx.userAgentHops = append(octx.userAgentHops, hop)
			intentIDSet[hop.IntentID] = true
		case "agent_app":
			octx.agentAppHops = append(octx.agentAppHops, hop)
			intentIDSet[hop.IntentID] = true
		case "agent_agent":
			octx.agentAgentHops = append(octx.agentAgentHops, hop)
			intentIDSet[hop.IntentID] = true
		default:
			ignoredCount++
		}
	}
	log.Printf("[observability] path=%s classified: userAgentHops=%d agentAppHops=%d agentAgentHops=%d ignored(unmatched from/to)=%d filteredByStatus=%d distinctIntents=%d",
		c.Request.URL.Path, len(octx.userAgentHops), len(octx.agentAppHops), len(octx.agentAgentHops), ignoredCount, statusFilteredCount, len(intentIDSet))
	if len(hops) > 0 && len(octx.userAgentHops) == 0 && len(octx.agentAppHops) == 0 {
		// Sample a few raw hops so a from/to DID that never matches any
		// registry (org_id mismatch, unlinked user DID, etc.) is visible
		// directly in the log instead of just "0 results, no error".
		sampleN := len(hops)
		if sampleN > 5 {
			sampleN = 5
		}
		for i := 0; i < sampleN; i++ {
			hop := hops[i]
			_, fromIsUser := users[hop.From]
			_, fromIsAgent := agents[hop.From]
			_, toIsAgent := agents[hop.To]
			_, toIsApp := apps[hop.To]
			log.Printf("[observability] path=%s unclassified sample hop: intent=%s from=%q(user=%v,agent=%v) to=%q(agent=%v,app=%v)",
				c.Request.URL.Path, hop.IntentID, hop.From, fromIsUser, fromIsAgent, hop.To, toIsAgent, toIsApp)
		}
	}

	intentIDs := make([]string, 0, len(intentIDSet))
	for id := range intentIDSet {
		intentIDs = append(intentIDs, id)
	}
	initiators, err := h.db.GetIntentInitiators(orgID, intentIDs)
	if err != nil {
		return nil, fmt.Errorf("fetch intent initiators: %w", err)
	}
	octx.intentInitiator = initiators

	return octx, nil
}

// obsScopeDID returns the DID to restrict hops to (non-admin) or "" (admin,
// no restriction).
func obsScopeDID(isAdmin bool, callerDID string) string {
	if isAdmin {
		return ""
	}
	return callerDID
}

// ---- GateEdge ---------------------------------------------------------

type obsGateWallCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

type obsGateWalls struct {
	Coca      *obsGateWallCounts `json:"coca"`
	Cbac      any                `json:"cbac"`
	Whitelist *obsGateWallCounts `json:"whitelist"`
}

type obsGateEdge struct {
	From     string        `json:"from"`
	To       string        `json:"to"`
	Count    int           `json:"count"`
	Allowed  int           `json:"allowed"`
	Elevated int           `json:"elevated"`
	Flagged  int           `json:"flagged"`
	Outcome  string        `json:"outcome"`
	LastAt   string        `json:"lastAt"`
	Policies []string      `json:"policies"`
	Walls    *obsGateWalls `json:"walls,omitempty"`
}

// buildGateEdges groups hops by (from,to) into GateEdge rows, ordered newest
// first. includeWalls should be true only for agent->app edges.
func buildGateEdges(hops []*db.ObsHop, includeWalls bool) []obsGateEdge {
	type acc struct {
		count, allowed, elevated, flagged int
		lastAt                            time.Time
		policies                          []string
		policySeen                        map[string]bool
		cocaPass, cocaFail                int
		wlPass, wlFail                    int
	}
	groups := map[[2]string]*acc{}
	var order [][2]string
	for _, hop := range hops {
		key := [2]string{hop.From, hop.To}
		a, exists := groups[key]
		if !exists {
			a = &acc{policySeen: map[string]bool{}}
			groups[key] = a
			order = append(order, key)
		}
		a.count++
		switch obsHopOutcome(hop.Threat, hop.Code) {
		case "flagged":
			a.flagged++
		case "elevated":
			a.elevated++
		default:
			a.allowed++
		}
		if hop.Time.After(a.lastAt) {
			a.lastAt = hop.Time
		}
		if p := obsHopPolicy(hop); p != nil && !a.policySeen[*p] {
			a.policySeen[*p] = true
			a.policies = append(a.policies, *p)
		}
		if includeWalls {
			if obsCocaResult(hop.Code) == "fail" {
				a.cocaFail++
			} else {
				a.cocaPass++
			}
			if obsWhitelistResult(hop.Code) == "fail" {
				a.wlFail++
			} else {
				a.wlPass++
			}
		}
	}

	edges := make([]obsGateEdge, 0, len(order))
	for _, key := range order {
		a := groups[key]
		outcome := "allowed"
		if a.flagged > 0 {
			outcome = "flagged"
		} else if a.elevated > 0 {
			outcome = "elevated"
		}
		policies := a.policies
		if policies == nil {
			policies = []string{}
		}
		edge := obsGateEdge{
			From: key[0], To: key[1],
			Count: a.count, Allowed: a.allowed, Elevated: a.elevated, Flagged: a.flagged,
			Outcome: outcome, LastAt: a.lastAt.UTC().Format(time.RFC3339),
			Policies: policies,
		}
		if includeWalls {
			edge.Walls = &obsGateWalls{
				Coca:      &obsGateWallCounts{Pass: a.cocaPass, Fail: a.cocaFail},
				Cbac:      nil,
				Whitelist: &obsGateWallCounts{Pass: a.wlPass, Fail: a.wlFail},
			}
		}
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].LastAt > edges[j].LastAt })
	return edges
}

// ---- Agent peers (v2) ---------------------------------------------------
//
// "Peer" is co-occurrence, not delegation: B is a peer of A if some intent
// initiated by U had both A and B take part — a direct A<->B message is not
// required. Participation is any hop, either direction, of any kind
// (user_agent/agent_app/agent_agent) that touches the agent.

// obsGroupHopsByIntent splits a hop slice into per-intent buckets.
func obsGroupHopsByIntent(hops []*db.ObsHop) map[string][]*db.ObsHop {
	out := map[string][]*db.ObsHop{}
	for _, hop := range hops {
		out[hop.IntentID] = append(out[hop.IntentID], hop)
	}
	return out
}

// obsIntentParticipants maps intentID -> set of agent DIDs that took part
// (any hop, either direction, any kind).
func obsIntentParticipants(userAgentHops, agentAppHops, agentAgentHops []*db.ObsHop) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(intentID, did string) {
		if out[intentID] == nil {
			out[intentID] = map[string]bool{}
		}
		out[intentID][did] = true
	}
	for _, hop := range userAgentHops {
		add(hop.IntentID, hop.To)
	}
	for _, hop := range agentAppHops {
		add(hop.IntentID, hop.From)
	}
	for _, hop := range agentAgentHops {
		add(hop.IntentID, hop.From)
		add(hop.IntentID, hop.To)
	}
	return out
}

// obsIntentApps maps intentID -> set of app DIDs reached in that intent,
// regardless of which agent made the call.
func obsIntentApps(agentAppHops []*db.ObsHop) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, hop := range agentAppHops {
		if out[hop.IntentID] == nil {
			out[hop.IntentID] = map[string]bool{}
		}
		out[hop.IntentID][hop.To] = true
	}
	return out
}

// obsUserIntents returns the distinct intent IDs initiated by userDID that
// have at least one classified hop (i.e. appear in the participants index).
func obsUserIntents(octx *obsContext, userDID string, participants map[string]map[string]bool) []string {
	var out []string
	for intentID := range participants {
		if octx.intentInitiator[intentID] == userDID {
			out = append(out, intentID)
		}
	}
	return out
}

// obsHopSummary is the {count, allowed, elevated, flagged, outcome, lastAt,
// policies} shape repeated across the peers/apps/involvedAgents payloads.
type obsHopSummary struct {
	Count    int      `json:"count"`
	Allowed  int      `json:"allowed"`
	Elevated int      `json:"elevated"`
	Flagged  int      `json:"flagged"`
	Outcome  string   `json:"outcome"`
	LastAt   string   `json:"lastAt"`
	Policies []string `json:"policies"`
}

func obsSummarizeHops(hops []*db.ObsHop) obsHopSummary {
	s := obsHopSummary{Outcome: "allowed"}
	policySeen := map[string]bool{}
	var lastAt time.Time
	for _, hop := range hops {
		s.Count++
		switch obsHopOutcome(hop.Threat, hop.Code) {
		case "flagged":
			s.Flagged++
		case "elevated":
			s.Elevated++
		default:
			s.Allowed++
		}
		s.Outcome = obsWorseOutcome(s.Outcome, obsHopOutcome(hop.Threat, hop.Code))
		if hop.Time.After(lastAt) {
			lastAt = hop.Time
		}
		if p := obsHopPolicy(hop); p != nil && !policySeen[*p] {
			policySeen[*p] = true
			s.Policies = append(s.Policies, *p)
		}
	}
	if s.Policies == nil {
		s.Policies = []string{}
	}
	s.LastAt = lastAt.UTC().Format(time.RFC3339)
	return s
}

// ---- 1. GET /dashboard/v1/observability-summary ------------------------

type obsGateStat struct {
	Checks   int     `json:"checks"`
	Pass     int     `json:"pass"`
	Fail     int     `json:"fail"`
	PassRate float64 `json:"passRate"`
}

func computeObsGateStat(hops []*db.ObsHop, result func(code int) string) obsGateStat {
	var pass, fail int
	for _, hop := range hops {
		if result(hop.Code) == "fail" {
			fail++
		} else {
			pass++
		}
	}
	checks := pass + fail
	rate := 0.0
	if checks > 0 {
		rate = float64(int(float64(pass)/float64(checks)*1000+0.5)) / 10
	}
	return obsGateStat{Checks: checks, Pass: pass, Fail: fail, PassRate: rate}
}

func (h *Handler) ObservabilitySummary(c *gin.Context) {
	_, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	rangeLabel, _ := obsParseRange(c)
	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	identitySet := map[string]bool{}
	agentSet := map[string]bool{}
	for _, hop := range octx.userAgentHops {
		identitySet[hop.From] = true
		agentSet[hop.To] = true
	}
	appSet := map[string]bool{}
	for _, hop := range octx.agentAppHops {
		agentSet[hop.From] = true
		appSet[hop.To] = true
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"range":            rangeLabel,
		"identities":       len(identitySet),
		"agents":           len(agentSet),
		"apps":             len(appSet),
		"toolInteractions": len(octx.agentAppHops),
		"gates": gin.H{
			"gate1Coca":      computeObsGateStat(octx.userAgentHops, obsCocaResult),
			"gate2Coca":      computeObsGateStat(octx.agentAppHops, obsCocaResult),
			"gate2Cbac":      nil,
			"gate2Whitelist": computeObsGateStat(octx.agentAppHops, obsWhitelistResult),
		},
	}})
}

// ---- 2. GET /dashboard/v1/observability-graph ---------------------------

func (h *Handler) ObservabilityGraph(c *gin.Context) {
	_, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	participants := obsIntentParticipants(octx.userAgentHops, octx.agentAppHops, octx.agentAgentHops)

	// usersCount = distinct initiators of any intent the agent took part in
	// (any hop kind, not just a direct user_agent hop) — this is what makes a
	// sub-agent that only ever appears in agent_agent hops still show up here
	// with a nonzero usersCount if its intents have real initiators.
	agentUsers := map[string]map[string]bool{}
	agentSeen := map[string]bool{}
	for intentID, agentSet := range participants {
		initiator := octx.intentInitiator[intentID]
		for agentDID := range agentSet {
			agentSeen[agentDID] = true
			if initiator == "" {
				continue
			}
			if agentUsers[agentDID] == nil {
				agentUsers[agentDID] = map[string]bool{}
			}
			agentUsers[agentDID][initiator] = true
		}
	}
	appSeen := map[string]bool{}
	for _, hop := range octx.agentAppHops {
		appSeen[hop.To] = true
	}

	agentDIDs := make([]string, 0, len(agentSeen))
	for did := range agentSeen {
		agentDIDs = append(agentDIDs, did)
	}
	sort.Strings(agentDIDs)
	agentsOut := make([]gin.H, 0, len(agentDIDs))
	for _, did := range agentDIDs {
		name, revoked := "", false
		if info := octx.agents[did]; info != nil {
			name, revoked = info.Name, info.Revoked
		}
		agentsOut = append(agentsOut, gin.H{
			"agentDID":   did,
			"agentName":  name,
			"handle":     name,
			"usersCount": len(agentUsers[did]),
			"revoked":    revoked,
		})
	}

	appDIDs := make([]string, 0, len(appSeen))
	for did := range appSeen {
		appDIDs = append(appDIDs, did)
	}
	sort.Strings(appDIDs)
	appsOut := make([]gin.H, 0, len(appDIDs))
	for _, did := range appDIDs {
		name := ""
		if info := octx.apps[did]; info != nil {
			name = info.Name
		}
		appsOut = append(appsOut, gin.H{"appDID": did, "appName": name, "operation": name})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"agents":        agentsOut,
		"apps":          appsOut,
		"agentAppEdges": buildGateEdges(octx.agentAppHops, true),
	}})
}

// ---- 3. GET /dashboard/v1/observability-users ---------------------------

func (h *Handler) ObservabilityUsers(c *gin.Context) {
	_, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	type userAgg struct {
		lastActiveAt time.Time
		hops         []*db.ObsHop
	}
	aggByDID := map[string]*userAgg{}
	var order []string
	for _, hop := range octx.userAgentHops {
		a, exists := aggByDID[hop.From]
		if !exists {
			a = &userAgg{}
			aggByDID[hop.From] = a
			order = append(order, hop.From)
		}
		a.hops = append(a.hops, hop)
		if hop.Time.After(a.lastActiveAt) {
			a.lastActiveAt = hop.Time
		}
	}

	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	type userOut struct {
		did          string
		name         string
		email        string
		lastActiveAt time.Time
		edges        []obsGateEdge
	}
	var users []userOut
	for _, did := range order {
		a := aggByDID[did]
		name, email := "", ""
		if info := octx.users[did]; info != nil {
			name, email = info.Name, info.Email
		}
		if search != "" && !strings.Contains(strings.ToLower(name+" "+email+" "+did), search) {
			continue
		}
		users = append(users, userOut{
			did: did, name: name, email: email,
			lastActiveAt: a.lastActiveAt,
			edges:        buildGateEdges(a.hops, false),
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].lastActiveAt.After(users[j].lastActiveAt) })

	page, pageSize := obsPagination(c, 30)
	total := len(users)
	pageUsers := obsSlicePage(users, page, pageSize)

	list := make([]gin.H, 0, len(pageUsers))
	for _, u := range pageUsers {
		list = append(list, gin.H{
			"userDID":      u.did,
			"userName":     u.name,
			"email":        u.email,
			"subtitle":     u.email,
			"kind":         "human",
			"signed":       true,
			"lastActiveAt": u.lastActiveAt.UTC().Format(time.RFC3339),
			"agentEdges":   u.edges,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"usersList":  list,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	}})
}

// ---- 4. GET /dashboard/v1/observability-user-flow -----------------------

func (h *Handler) ObservabilityUserFlow(c *gin.Context) {
	orgID, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	userDID := c.Query("userDID")
	if userDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "userDID is required"})
		return
	}
	if !isAdmin && userDID != callerDID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "forbidden"})
		return
	}
	exists, err := h.db.OrgUserExists(orgID, userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to look up user: %v", err)})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "user not found"})
		return
	}

	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	var userAgentForUser []*db.ObsHop
	for _, hop := range octx.userAgentHops {
		if hop.From == userDID {
			userAgentForUser = append(userAgentForUser, hop)
		}
	}
	var agentAppForUser []*db.ObsHop
	for _, hop := range octx.agentAppHops {
		if octx.intentInitiator[hop.IntentID] == userDID {
			agentAppForUser = append(agentAppForUser, hop)
		}
	}

	// involvedAgents: every agent that took part (any hop, any kind) in any of
	// U's intents — lets the UI make every agent in the user's intents
	// clickable, not just the entry agent they messaged directly.
	byIntentUA := obsGroupHopsByIntent(octx.userAgentHops)
	byIntentAA := obsGroupHopsByIntent(octx.agentAgentHops)
	byIntentAP := obsGroupHopsByIntent(octx.agentAppHops)
	participants := obsIntentParticipants(octx.userAgentHops, octx.agentAppHops, octx.agentAgentHops)
	userIntents := obsUserIntents(octx, userDID, participants)

	agentHops := map[string][]*db.ObsHop{}
	agentIntents := map[string]map[string]bool{}
	var agentOrder []string
	for _, intentID := range userIntents {
		all := make([]*db.ObsHop, 0)
		all = append(all, byIntentUA[intentID]...)
		all = append(all, byIntentAA[intentID]...)
		all = append(all, byIntentAP[intentID]...)
		for agentDID := range participants[intentID] {
			if _, exists := agentHops[agentDID]; !exists {
				agentOrder = append(agentOrder, agentDID)
				agentIntents[agentDID] = map[string]bool{}
			}
			agentIntents[agentDID][intentID] = true
			for _, hop := range all {
				if hop.From == agentDID || hop.To == agentDID {
					agentHops[agentDID] = append(agentHops[agentDID], hop)
				}
			}
		}
	}
	sort.Strings(agentOrder)
	involvedAgents := make([]gin.H, 0, len(agentOrder))
	for _, agentDID := range agentOrder {
		summary := obsSummarizeHops(agentHops[agentDID])
		involvedAgents = append(involvedAgents, gin.H{
			"agentDID":     agentDID,
			"count":        summary.Count,
			"intentsCount": len(agentIntents[agentDID]),
			"outcome":      summary.Outcome,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"userDID":        userDID,
		"agentEdges":     buildGateEdges(userAgentForUser, false),
		"agentAppEdges":  buildGateEdges(agentAppForUser, true),
		"involvedAgents": involvedAgents,
	}})
}

// ---- 4b. GET /dashboard/v1/observability-agent-flow ----------------------

func (h *Handler) ObservabilityAgentFlow(c *gin.Context) {
	orgID, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	userDID := c.Query("userDID")
	agentDID := c.Query("agentDID")
	peerDID := c.Query("peerDID")
	if userDID == "" || agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "userDID and agentDID are required"})
		return
	}
	if !isAdmin && userDID != callerDID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "forbidden"})
		return
	}
	exists, err := h.db.OrgUserExists(orgID, userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to look up user: %v", err)})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "user not found"})
		return
	}

	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}
	if _, ok := octx.agents[agentDID]; !ok {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "agent not found"})
		return
	}
	if peerDID != "" {
		if _, ok := octx.agents[peerDID]; !ok {
			c.JSON(http.StatusNotFound, Response{Status: false, Message: "agent not found"})
			return
		}
	}

	byIntentUA := obsGroupHopsByIntent(octx.userAgentHops)
	byIntentAA := obsGroupHopsByIntent(octx.agentAgentHops)
	byIntentAP := obsGroupHopsByIntent(octx.agentAppHops)
	participants := obsIntentParticipants(octx.userAgentHops, octx.agentAppHops, octx.agentAgentHops)
	intentApps := obsIntentApps(octx.agentAppHops)

	// U's intents where A took part.
	var aIntents []string
	for _, intentID := range obsUserIntents(octx, userDID, participants) {
		if participants[intentID][agentDID] {
			aIntents = append(aIntents, intentID)
		}
	}

	// Peers: every other agent that shared at least one of aIntents with A.
	// Returned the same regardless of peerDID (per spec).
	type peerAgg struct {
		hops           []*db.ObsHop
		intents        map[string]bool
		sent, received int
	}
	peers := map[string]*peerAgg{}
	var peerOrder []string
	for _, intentID := range aIntents {
		var intentHops []*db.ObsHop
		intentHops = append(intentHops, byIntentUA[intentID]...)
		intentHops = append(intentHops, byIntentAA[intentID]...)
		intentHops = append(intentHops, byIntentAP[intentID]...)
		for otherDID := range participants[intentID] {
			if otherDID == agentDID {
				continue
			}
			p, exists := peers[otherDID]
			if !exists {
				p = &peerAgg{intents: map[string]bool{}}
				peers[otherDID] = p
				peerOrder = append(peerOrder, otherDID)
			}
			p.intents[intentID] = true
			for _, hop := range intentHops {
				// count/allowed/elevated/flagged/outcome/lastAt/policies are
				// exactly A<->peer traffic — hops directly between the two,
				// not every hop either of them happens to have with anyone
				// else in the shared intent.
				if hop.From == agentDID && hop.To == otherDID {
					p.hops = append(p.hops, hop)
					p.sent++
				}
				if hop.From == otherDID && hop.To == agentDID {
					p.hops = append(p.hops, hop)
					p.received++
				}
			}
		}
	}
	sort.Strings(peerOrder)
	peersOut := make([]gin.H, 0, len(peerOrder))
	for _, peer := range peerOrder {
		p := peers[peer]
		name, revoked := "", false
		if info := octx.agents[peer]; info != nil {
			name, revoked = info.Name, info.Revoked
		}
		var direct any
		if p.sent > 0 || p.received > 0 {
			direct = gin.H{"sent": p.sent, "received": p.received}
		}
		summary := obsSummarizeHops(p.hops)
		peersOut = append(peersOut, gin.H{
			"agentDID":     peer,
			"agentName":    name,
			"handle":       name,
			"revoked":      revoked,
			"direct":       direct,
			"intentsCount": len(p.intents),
			"count":        summary.Count,
			"allowed":      summary.Allowed,
			"elevated":     summary.Elevated,
			"flagged":      summary.Flagged,
			"outcome":      summary.Outcome,
			"lastAt":       summary.LastAt,
			"policies":     summary.Policies,
		})
	}

	// Apps: without peerDID, every app in aIntents; with peerDID, only apps in
	// the intents A and B actually share (peers[peerDID].intents).
	relevantIntents := aIntents
	if peerDID != "" {
		relevantIntents = nil
		if p, ok := peers[peerDID]; ok {
			for intentID := range p.intents {
				relevantIntents = append(relevantIntents, intentID)
			}
		}
	}

	type appAgg struct {
		hops         []*db.ObsHop
		intents      map[string]bool
		calledByHops map[string][]*db.ObsHop
	}
	apps := map[string]*appAgg{}
	var appOrder []string
	for _, intentID := range relevantIntents {
		for appDID := range intentApps[intentID] {
			a, exists := apps[appDID]
			if !exists {
				a = &appAgg{intents: map[string]bool{}, calledByHops: map[string][]*db.ObsHop{}}
				apps[appDID] = a
				appOrder = append(appOrder, appDID)
			}
			a.intents[intentID] = true
			for _, hop := range byIntentAP[intentID] {
				if hop.To != appDID {
					continue
				}
				a.hops = append(a.hops, hop)
				a.calledByHops[hop.From] = append(a.calledByHops[hop.From], hop)
			}
		}
	}
	sort.Strings(appOrder)
	appsOut := make([]gin.H, 0, len(appOrder))
	for _, appDID := range appOrder {
		a := apps[appDID]
		name := ""
		if info := octx.apps[appDID]; info != nil {
			name = info.Name
		}
		var callerOrder []string
		for caller := range a.calledByHops {
			callerOrder = append(callerOrder, caller)
		}
		sort.Strings(callerOrder)
		calledBy := make([]gin.H, 0, len(callerOrder))
		for _, caller := range callerOrder {
			callerSummary := obsSummarizeHops(a.calledByHops[caller])
			calledBy = append(calledBy, gin.H{
				"agentDID": caller,
				"count":    callerSummary.Count,
				"outcome":  callerSummary.Outcome,
			})
		}
		summary := obsSummarizeHops(a.hops)
		appsOut = append(appsOut, gin.H{
			"appDID":       appDID,
			"appName":      name,
			"calledBy":     calledBy,
			"intentsCount": len(a.intents),
			"count":        summary.Count,
			"allowed":      summary.Allowed,
			"elevated":     summary.Elevated,
			"flagged":      summary.Flagged,
			"outcome":      summary.Outcome,
			"lastAt":       summary.LastAt,
			"policies":     summary.Policies,
		})
	}

	var peerDIDOut any
	if peerDID != "" {
		peerDIDOut = peerDID
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"userDID":  userDID,
		"agentDID": agentDID,
		"peerDID":  peerDIDOut,
		"peers":    peersOut,
		"apps":     appsOut,
	}})
}

// ---- 5. GET /dashboard/v1/observability-intents -------------------------

func (h *Handler) ObservabilityIntents(c *gin.Context) {
	orgID, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	userDID := c.Query("userDID")
	agentDID := c.Query("agentDID")
	peerDID := c.Query("peerDID")
	appDID := c.Query("appDID")
	if userDID == "" || agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "userDID and agentDID are required"})
		return
	}
	if !isAdmin && userDID != callerDID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "forbidden"})
		return
	}

	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	byIntentUA := obsGroupHopsByIntent(octx.userAgentHops)
	byIntentAA := obsGroupHopsByIntent(octx.agentAgentHops)
	byIntentAP := obsGroupHopsByIntent(octx.agentAppHops)
	participants := obsIntentParticipants(octx.userAgentHops, octx.agentAppHops, octx.agentAgentHops)
	intentApps := obsIntentApps(octx.agentAppHops)

	// Qualifying intents: userDID's own intents where agentDID took part (any
	// hop kind — agentDID need not be someone the user messaged directly),
	// and, if given, where peerDID also took part.
	var intentIDs []string
	for _, intentID := range obsUserIntents(octx, userDID, participants) {
		if !participants[intentID][agentDID] {
			continue
		}
		if peerDID != "" && !participants[intentID][peerDID] {
			continue
		}
		if appDID != "" && !intentApps[intentID][appDID] {
			continue
		}
		intentIDs = append(intentIDs, intentID)
	}

	infoMap, err := h.db.GetObsIntentInfo(orgID, intentIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load intent info: %v", err)})
		return
	}

	type outRow struct {
		intentID          string
		title             string
		outcome           string
		policy            *string
		flags             int
		interactionsCount int
		appDIDs           []string
		agents            []gin.H
		appCalls          []gin.H
		startedAt         time.Time
		lastAt            time.Time
		reviewStatus      string
	}
	results := make([]outRow, 0, len(intentIDs))
	for _, id := range intentIDs {
		var allHops []*db.ObsHop
		allHops = append(allHops, byIntentUA[id]...)
		allHops = append(allHops, byIntentAA[id]...)
		allHops = append(allHops, byIntentAP[id]...)

		outcome := "allowed"
		flags := 0
		var lastAt time.Time
		for _, hop := range allHops {
			o := obsHopOutcome(hop.Threat, hop.Code)
			outcome = obsWorseOutcome(outcome, o)
			if o == "flagged" {
				flags++
			}
			if hop.Time.After(lastAt) {
				lastAt = hop.Time
			}
		}

		apps := make([]string, 0, len(intentApps[id]))
		for app := range intentApps[id] {
			apps = append(apps, app)
		}
		sort.Strings(apps)

		agentDIDs := make([]string, 0, len(participants[id]))
		for a := range participants[id] {
			agentDIDs = append(agentDIDs, a)
		}
		sort.Strings(agentDIDs)
		agentsOut := make([]gin.H, 0, len(agentDIDs))
		for _, a := range agentDIDs {
			name := ""
			if info := octx.agents[a]; info != nil {
				name = info.Name
			}
			agentsOut = append(agentsOut, gin.H{"did": a, "name": name})
		}

		type callKey struct{ agentDID, appDID string }
		callCounts := map[callKey]int{}
		var callOrder []callKey
		for _, hop := range byIntentAP[id] {
			k := callKey{hop.From, hop.To}
			if _, exists := callCounts[k]; !exists {
				callOrder = append(callOrder, k)
			}
			callCounts[k]++
		}
		appCallsOut := make([]gin.H, 0, len(callOrder))
		for _, k := range callOrder {
			appCallsOut = append(appCallsOut, gin.H{"agentDID": k.agentDID, "appDID": k.appDID, "count": callCounts[k]})
		}

		title, reviewStatus, startedAt := "", "Ongoing", lastAt
		if info := infoMap[id]; info != nil {
			title, reviewStatus, startedAt = info.Title, info.ReviewStatus, info.StartedAt
		}
		results = append(results, outRow{
			intentID: id, title: title, outcome: outcome, policy: obsWorstPolicy(allHops),
			flags: flags, interactionsCount: len(allHops), appDIDs: apps,
			agents: agentsOut, appCalls: appCallsOut,
			startedAt: startedAt, lastAt: lastAt, reviewStatus: reviewStatus,
		})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].lastAt.After(results[j].lastAt) })

	page, pageSize := obsPagination(c, 50)
	total := len(results)
	pageResults := obsSlicePage(results, page, pageSize)

	list := make([]gin.H, 0, len(pageResults))
	for _, r := range pageResults {
		list = append(list, gin.H{
			"intentID":          r.intentID,
			"intentTitle":       r.title,
			"outcome":           r.outcome,
			"policy":            r.policy,
			"flags":             r.flags,
			"interactionsCount": r.interactionsCount,
			"appDIDs":           r.appDIDs,
			"agents":            r.agents,
			"appCalls":          r.appCalls,
			"startedAt":         r.startedAt.UTC().Format(time.RFC3339),
			"lastAt":            r.lastAt.UTC().Format(time.RFC3339),
			"reviewStatus":      r.reviewStatus,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"intentsList": list,
		"total":       total,
		"page":        page,
		"pageSize":    pageSize,
		"totalPages":  (total + pageSize - 1) / pageSize,
	}})
}

// ---- 6. GET /dashboard/v1/observability-paths ---------------------------

// obsFineRow is one (user, agent, app|none, intent) tuple before any
// collapsing — the finest grain the data can be broken into.
type obsFineRow struct {
	userDID, agentDID, appDID, intentID string
	userHops, appHops                   []*db.ObsHop
}

// obsFullIntentDetail returns the same shape /dashboard/v1/intent-info does
// (full metadata plus every interaction in the intent) — used to expand a
// path row's "intent" field from a bare {id, title} into the complete
// picture instead of a dead end. Returns just {id} if the intent can't be
// loaded (should not normally happen since the id came from real hop data).
//
// title is passed in rather than read off GetIntentInfo's result: that query
// (shared with /intent-info) never selects a title at all, whereas
// GetObsIntentInfo already computes one (the first interaction's message)
// for every caller in this file.
func (h *Handler) obsFullIntentDetail(intentID, title string) gin.H {
	intent, err := h.db.GetIntentInfo(intentID)
	if err != nil {
		return gin.H{"id": intentID, "title": firstNWords(title, 5), "titleFull": title}
	}
	interactions, err := h.db.GetInteractionsByIntent(intentID)
	if err != nil {
		interactions = nil
	}

	// threat_detected on new_intents is written once by handleIntentWorkflow at
	// intent-creation time and never recomputed — it can drift stale relative
	// to the interactions' own threat flags. Derive it live from the same
	// interaction rows /interactions-list reads instead of trusting that
	// stored column, so the two endpoints can't disagree.
	threatDetected := false
	provenanceRecordID := ""
	txns := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		if i.Threat {
			threatDetected = true
		}
		if provenanceRecordID == "" && i.ProvenanceRecordID != "" {
			provenanceRecordID = i.ProvenanceRecordID
		}
		txns = append(txns, gin.H{
			"interactionID":      i.InteractionID,
			"from":               i.From,
			"fromName":           i.FromName,
			"to":                 i.To,
			"toName":             i.ToName,
			"type":               i.Type,
			"direction":          i.Direction,
			"threat":             i.Threat,
			"threatID":           i.ThreatID,
			"time":               i.Time,
			"message":            i.Message,
			"signature":          i.Signature,
			"provenanceReqID":    i.ProvenanceReqID,
			"provenanceRecordID": i.ProvenanceRecordID,
		})
	}

	return gin.H{
		"id":                 intent.IntentID,
		"title":              firstNWords(title, 5),
		"titleFull":          title,
		"initiatorDID":       intent.InitiatorDID,
		"initiatorName":      intent.InitiatorName,
		"startedAt":          intent.StartedAt,
		"status":             intent.Status,
		"reviewStatus":       intent.ReviewStatus,
		"threatDetected":     threatDetected,
		"flowType":           intent.FlowType,
		"executor":           intent.Executor,
		"chainDepth":         intent.ChainDepth,
		"interactionsCount":  intent.InteractionsCount,
		"agentsCount":        intent.AgentsCount,
		"toolsCount":         intent.ToolsCount,
		"firstInteractionAt": intent.FirstInteractionAt,
		"lastInteractionAt":  intent.LastInteractionAt,
		"runtimeSeconds":     intent.RuntimeSeconds,
		"provenanceRecordID": provenanceRecordID,
		"interactions":       txns,
	}
}

func (h *Handler) ObservabilityPaths(c *gin.Context) {
	orgID, isAdmin, callerDID, ok := h.obsScope(c)
	if !ok {
		return
	}
	fUser := c.Query("userDID")
	fAgent := c.Query("agentDID")
	fPeer := c.Query("peerDID")
	fApp := c.Query("appDID")
	fIntent := c.Query("intentID")

	if !isAdmin && fUser != "" && fUser != callerDID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "forbidden"})
		return
	}

	octx, err := h.loadObsContext(c, obsScopeDID(isAdmin, callerDID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load observability data: %v", err)})
		return
	}

	// participants indexes which agents took part in which intent (any hop,
	// any kind) — used only to apply the peerDID filter; it does not change
	// how agent/app rows are built below.
	participants := obsIntentParticipants(octx.userAgentHops, octx.agentAppHops, octx.agentAgentHops)

	// Group user_agent hops by (intent, agent).
	type uaKey struct{ intentID, agentDID string }
	uaGroups := map[uaKey][]*db.ObsHop{}
	for _, hop := range octx.userAgentHops {
		uid := octx.intentInitiator[hop.IntentID]
		if fUser != "" && uid != fUser {
			continue
		}
		key := uaKey{hop.IntentID, hop.To}
		uaGroups[key] = append(uaGroups[key], hop)
	}
	// Group agent_app hops by (intent, app) — not by which agent actually made
	// the call. An app reached indirectly (agentDID delegated to another
	// agent, which then called the app) must still surface against
	// agentDID's row instead of dead-ending, so the app leg is matched purely
	// by intent, never by requiring the same agent on both legs.
	type aaKey struct{ intentID, appDID string }
	aaGroups := map[aaKey][]*db.ObsHop{}
	for _, hop := range octx.agentAppHops {
		uid := octx.intentInitiator[hop.IntentID]
		if fUser != "" && uid != fUser {
			continue
		}
		key := aaKey{hop.IntentID, hop.To}
		aaGroups[key] = append(aaGroups[key], hop)
	}

	var fine []obsFineRow
	for key, uaHops := range uaGroups {
		if fAgent != "" && key.agentDID != fAgent {
			continue
		}
		if fIntent != "" && key.intentID != fIntent {
			continue
		}
		if fPeer != "" && !participants[key.intentID][fPeer] {
			continue
		}
		userDID := octx.intentInitiator[key.intentID]
		if userDID == "" {
			continue
		}

		foundApp := false
		for aKey, appHops := range aaGroups {
			if aKey.intentID != key.intentID {
				continue
			}
			if fApp != "" && aKey.appDID != fApp {
				continue
			}
			foundApp = true
			fine = append(fine, obsFineRow{
				userDID: userDID, agentDID: key.agentDID, appDID: aKey.appDID, intentID: key.intentID,
				userHops: uaHops, appHops: appHops,
			})
		}
		if !foundApp && fApp == "" {
			fine = append(fine, obsFineRow{
				userDID: userDID, agentDID: key.agentDID, appDID: "", intentID: key.intentID,
				userHops: uaHops, appHops: nil,
			})
		}
	}

	// Both userDID and agentDID picked -> one row per (user,agent,app,intent).
	// Otherwise -> one row per (user,agent,app), summed across intents. When
	// both agentDID and peerDID are set, per-intent grain also applies (one
	// row per (user,agent,peer,app,intent)) even without userDID.
	collapse := !(fUser != "" && fAgent != "") && !(fAgent != "" && fPeer != "")

	type rowKey struct{ userDID, agentDID, peerDID, appDID, intentID string }
	type rowAgg struct {
		key      rowKey
		userHops []*db.ObsHop
		appHops  []*db.ObsHop
	}
	rows := map[rowKey]*rowAgg{}
	var rowOrder []rowKey
	for _, f := range fine {
		key := rowKey{f.userDID, f.agentDID, fPeer, f.appDID, f.intentID}
		if collapse {
			key.intentID = ""
		}
		r, exists := rows[key]
		if !exists {
			r = &rowAgg{key: key}
			rows[key] = r
			rowOrder = append(rowOrder, key)
		}
		r.userHops = append(r.userHops, f.userHops...)
		r.appHops = append(r.appHops, f.appHops...)
	}

	var neededIntentIDs []string
	if !collapse {
		for _, key := range rowOrder {
			neededIntentIDs = append(neededIntentIDs, key.intentID)
		}
	}
	intentInfo, err := h.db.GetObsIntentInfo(orgID, neededIntentIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to load intent info: %v", err)})
		return
	}

	type gate2 struct {
		cocaResult, wlResult string
		count                int
	}
	type outRow struct {
		key               rowKey
		userName          string
		agentName         string
		appName           string
		hasApp            bool
		intentTitle       string
		hasIntent         bool
		gate1Result       string
		gate1Count        int
		gate2             *gate2
		interactionsCount int
		outcome           string
		policy            *string
		lastAt            time.Time
	}
	outRows := make([]outRow, 0, len(rowOrder))
	for _, key := range rowOrder {
		r := rows[key]
		userName, agentName, appName := "", "", ""
		if info := octx.users[key.userDID]; info != nil {
			userName = info.Name
		}
		if info := octx.agents[key.agentDID]; info != nil {
			agentName = info.Name
		}
		hasApp := key.appDID != ""
		if hasApp {
			if info := octx.apps[key.appDID]; info != nil {
				appName = info.Name
			}
		}

		gate1Result := "pass"
		for _, hop := range r.userHops {
			if obsCocaResult(hop.Code) == "fail" {
				gate1Result = "fail"
				break
			}
		}

		var g2 *gate2
		if hasApp {
			cocaResult, wlResult := "pass", "pass"
			for _, hop := range r.appHops {
				if obsCocaResult(hop.Code) == "fail" {
					cocaResult = "fail"
				}
				if obsWhitelistResult(hop.Code) == "fail" {
					wlResult = "fail"
				}
			}
			g2 = &gate2{cocaResult: cocaResult, wlResult: wlResult, count: len(r.appHops)}
		}

		allHops := make([]*db.ObsHop, 0, len(r.userHops)+len(r.appHops))
		allHops = append(allHops, r.userHops...)
		allHops = append(allHops, r.appHops...)
		outcome := "allowed"
		var lastAt time.Time
		for _, hop := range allHops {
			outcome = obsWorseOutcome(outcome, obsHopOutcome(hop.Threat, hop.Code))
			if hop.Time.After(lastAt) {
				lastAt = hop.Time
			}
		}

		hasIntent := !collapse
		intentTitle := ""
		if hasIntent {
			if info := intentInfo[key.intentID]; info != nil {
				intentTitle = info.Title
			}
		}

		outRows = append(outRows, outRow{
			key: key, userName: userName, agentName: agentName, appName: appName, hasApp: hasApp,
			intentTitle: intentTitle, hasIntent: hasIntent,
			gate1Result: gate1Result, gate1Count: len(r.userHops), gate2: g2,
			interactionsCount: len(allHops), outcome: outcome, policy: obsWorstPolicy(allHops),
			lastAt: lastAt,
		})
	}
	sort.Slice(outRows, func(i, j int) bool { return outRows[i].lastAt.After(outRows[j].lastAt) })

	page, pageSize := obsPagination(c, 50)
	total := len(outRows)
	pageRows := obsSlicePage(outRows, page, pageSize)

	// Full intent detail (every interaction, not just id/title) is only
	// fetched for the intents actually being returned on this page — avoids
	// re-fetching per row when the same intent repeats, and never touches
	// rows outside the current page.
	fullIntents := map[string]gin.H{}
	for _, r := range pageRows {
		if !r.hasIntent {
			continue
		}
		if _, done := fullIntents[r.key.intentID]; done {
			continue
		}
		fullIntents[r.key.intentID] = h.obsFullIntentDetail(r.key.intentID, r.intentTitle)
	}

	list := make([]gin.H, 0, len(pageRows))
	for _, r := range pageRows {
		var appOut any
		if r.hasApp {
			appOut = gin.H{"did": r.key.appDID, "name": r.appName}
		}
		var intentOut any
		if r.hasIntent {
			intentOut = fullIntents[r.key.intentID]
		}
		var gate2Out any
		if r.gate2 != nil {
			gate2Out = gin.H{
				"coca":      gin.H{"result": r.gate2.cocaResult, "count": r.gate2.count},
				"cbac":      gin.H{"result": "not_tracked", "count": r.gate2.count},
				"whitelist": gin.H{"result": r.gate2.wlResult, "count": r.gate2.count},
			}
		}
		var peerOut any
		if r.key.peerDID != "" {
			peerName := ""
			if info := octx.agents[r.key.peerDID]; info != nil {
				peerName = info.Name
			}
			peerOut = gin.H{"did": r.key.peerDID, "name": peerName}
		}
		list = append(list, gin.H{
			"user":              gin.H{"did": r.key.userDID, "name": r.userName},
			"agent":             gin.H{"did": r.key.agentDID, "name": r.agentName},
			"peer":              peerOut,
			"app":               appOut,
			"intent":            intentOut,
			"gate1":             gin.H{"result": r.gate1Result, "count": r.gate1Count},
			"gate2":             gate2Out,
			"interactionsCount": r.interactionsCount,
			"outcome":           r.outcome,
			"policy":            r.policy,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"pathsList":  list,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	}})
}
