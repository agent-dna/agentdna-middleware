package handler

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"agentdna-ratelimit-auth/db"

	"github.com/gin-gonic/gin"
)

// authEvidenceInput is one record as an observation point sends it.
type authEvidenceInput struct {
	RequestID    string  `json:"request_id"`
	Source       string  `json:"source"`
	RunID        string  `json:"run_id"`
	AuthMethod   string  `json:"auth_method"`
	CredentialID string  `json:"credential_id"`
	IdentityID   *string `json:"identity_id"`
	AuthStatus   string  `json:"auth_status"`
	KeyVersion   string  `json:"key_version"`
	Destination  string  `json:"destination"`

	// Seconds since 1970, from the observer's own clock. A pointer so a
	// record that leaves it out is stored with the database's time instead.
	ObservedAt *float64 `json:"observed_at"`
}

// StoreAuthEvidence takes authentication evidence from an observation point.
//
//	POST /core/v1/auth-evidence
//	Header: X-API-Key: <api_key>
//	Body:   {"records": [ ... ]}
//
// A batch, because one run makes many calls and a request per call from inside
// a request path is a lot of connections.
//
// Nothing is checked against a workflow here: the signed chain only arrives
// when the run finishes. Records are stored as they come and matched at read
// time, which is also what quarantines records naming a request we never saw.
func (h *Handler) StoreAuthEvidence(c *gin.Context) {
	user, ok := h.userFromAPIKey(c)
	if !ok {
		return
	}

	var body struct {
		Records []authEvidenceInput `json:"records"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid body"})
		return
	}

	stored := 0
	for _, in := range body.Records {
		if in.RequestID == "" || in.Source == "" {
			continue
		}
		record := &db.AuthEvidenceRecord{
			RequestID:    in.RequestID,
			Source:       in.Source,
			RunID:        in.RunID,
			AuthMethod:   in.AuthMethod,
			CredentialID: in.CredentialID,
			IdentityID:   in.IdentityID,
			AuthStatus:   in.AuthStatus,
			KeyVersion:   in.KeyVersion,
			Destination:  in.Destination,
			ObservedAt:   in.ObservedAt,
		}
		if err := h.db.StoreAuthEvidence(record, user.OrgID); err == nil {
			stored++
		}
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"stored": stored}})
}

// authEvidenceRow is one stored auth_evidence row as the dashboard sees it.
type authEvidenceRow struct {
	RequestID    string     `json:"requestID"`
	Source       string     `json:"source"`
	RunID        string     `json:"runID"`
	AuthMethod   string     `json:"authMethod"`
	CredentialID string     `json:"credentialID"`
	IdentityID   *string    `json:"identityID"`
	AuthStatus   string     `json:"authStatus"`
	KeyVersion   string     `json:"keyVersion"`
	Destination  string     `json:"destination"`
	ObservedAt   *time.Time `json:"observedAt"`
}

// interactionAuthEvidence is one interaction of the intent with the evidence
// rows whose request_id matches its signature.
type interactionAuthEvidence struct {
	// Sequence is the 1-based place in the response; Position is the hop's
	// depth in the run and Branch its branch letter ("" on the trunk), so two
	// branches can share a Position but never a Sequence.
	Sequence      int               `json:"sequence"`
	Position      int               `json:"position"`
	Branch        string            `json:"branch"`
	InteractionID string            `json:"interactionID"`
	Signature     string            `json:"signature"`
	From          string            `json:"from"`
	FromName      string            `json:"fromName"`
	To            string            `json:"to"`
	ToName        string            `json:"toName"`
	Type          string            `json:"type"`
	Time          time.Time         `json:"time"`
	Evidence      []authEvidenceRow `json:"evidence"`
}

// buildIntentAuthEvidence lines evidence up with the intent's interactions in
// hop order (see interactionOrder), keeping only interactions that have at least one evidence row.
// Rows within a hop are ordered by observation time, then source, then
// destination, so the same evidence always reads the same way.
func buildIntentAuthEvidence(
	interactions []*db.InteractionRecord,
	byRequest map[string][]*db.AuthEvidenceRecord,
) []interactionAuthEvidence {
	byID := make(map[string]*db.InteractionRecord, len(interactions))
	for _, i := range interactions {
		byID[i.InteractionID] = i
	}

	out := make([]interactionAuthEvidence, 0)
	for _, ref := range interactionOrder(interactions) {
		records := byRequest[ref.Signature]
		if ref.Signature == "" || len(records) == 0 {
			continue
		}

		rows := make([]authEvidenceRow, 0, len(records))
		for _, r := range records {
			row := authEvidenceRow{
				RequestID:    r.RequestID,
				Source:       r.Source,
				RunID:        r.RunID,
				AuthMethod:   r.AuthMethod,
				CredentialID: r.CredentialID,
				IdentityID:   r.IdentityID,
				AuthStatus:   r.AuthStatus,
				KeyVersion:   r.KeyVersion,
				Destination:  r.Destination,
			}
			if r.ObservedAt != nil {
				t := time.UnixMicro(int64(*r.ObservedAt * 1e6)).UTC()
				row.ObservedAt = &t
			}
			rows = append(rows, row)
		}
		sort.SliceStable(rows, func(a, b int) bool {
			ta, tb := rows[a].ObservedAt, rows[b].ObservedAt
			if ta != nil && tb != nil && !ta.Equal(*tb) {
				return ta.Before(*tb)
			}
			if rows[a].Source != rows[b].Source {
				return rows[a].Source < rows[b].Source
			}
			return rows[a].Destination < rows[b].Destination
		})

		i := byID[ref.InteractionID]
		out = append(out, interactionAuthEvidence{
			Sequence:      len(out) + 1,
			Position:      ref.Position,
			Branch:        ref.Branch,
			InteractionID: i.InteractionID,
			Signature:     i.Signature,
			From:          i.From,
			FromName:      i.FromName,
			To:            i.To,
			ToName:        i.ToName,
			Type:          i.Type,
			Time:          i.Time,
			Evidence:      rows,
		})
	}
	return out
}

// IntentAuthEvidence returns the auth_evidence rows recorded for one intent,
// grouped under the interaction whose signature they match, in hop order.
// Interactions without any evidence are left out.
//
//	GET /dashboard/v1/intent-auth-evidence?intentID=<intentID>
func (h *Handler) IntentAuthEvidence(c *gin.Context) {
	intentID := c.Query("intentID")
	orgID := c.GetString(CtxOrgID)
	if intentID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "intentID is required"})
		return
	}

	intent, err := h.db.GetIntentInfo(intentID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "intent not found"})
		return
	}
	if intent.OrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	interactions, err := h.db.GetInteractionsByIntent(intentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}
	byRequest, err := h.db.GetAuthEvidenceByIntent(intentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch auth evidence: %v", err)})
		return
	}

	hops := buildIntentAuthEvidence(interactions, byRequest)
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"intentID":          intentID,
		"totalInteractions": len(interactions),
		"count":             len(hops),
		"interactions":      hops,
	}})
}
