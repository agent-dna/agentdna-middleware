package handler

import (
	"fmt"
	"log"
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
		log.Printf("[auth-evidence] store: rejected, API key check failed status=%d", c.Writer.Status())
		return
	}

	var body struct {
		Records []authEvidenceInput `json:"records"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Printf("[auth-evidence] store: invalid body org=%s err=%v", user.OrgID, err)
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid body"})
		return
	}
	log.Printf("[auth-evidence] store: received %d record(s) org=%s", len(body.Records), user.OrgID)

	stored := 0
	for idx, in := range body.Records {
		log.Printf("[auth-evidence] store: record[%d] request_id=%q source=%q run_id=%q auth_method=%q credential_id=%q identity_id=%s auth_status=%q key_version=%q destination=%q observed_at=%s",
			idx, in.RequestID, in.Source, in.RunID, in.AuthMethod, in.CredentialID, logStrPtr(in.IdentityID),
			in.AuthStatus, in.KeyVersion, in.Destination, logFloatPtr(in.ObservedAt))
		if in.RequestID == "" || in.Source == "" {
			log.Printf("[auth-evidence] store: record[%d] SKIPPED: request_id and source are required", idx)
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
		inserted, err := h.db.StoreAuthEvidence(record, user.OrgID)
		switch {
		case err != nil:
			log.Printf("[auth-evidence] store: record[%d] request_id=%q FAILED: %v", idx, in.RequestID, err)
		case !inserted:
			log.Printf("[auth-evidence] store: record[%d] request_id=%q source=%q destination=%q already stored, ignored", idx, in.RequestID, in.Source, in.Destination)
		default:
			log.Printf("[auth-evidence] store: record[%d] request_id=%q stored", idx, in.RequestID)
			stored++
			if record.Source == SourceServerOut {
				h.recordResourceAccess(idx, record)
			}
		}
	}
	log.Printf("[auth-evidence] store: stored %d of %d record(s) org=%s", stored, len(body.Records), user.OrgID)

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"stored": stored}})
}

// recordResourceAccess adds a stored server_out record to resources. When the
// request's interaction has not landed yet nothing is written here; the
// interaction side picks it up (RecordResourcesForRequest).
//
// A failure is logged, not returned: the evidence itself is already stored.
func (h *Handler) recordResourceAccess(idx int, r *db.AuthEvidenceRecord) {
	n, err := h.db.RecordResourceAccess(r.RequestID, r.Destination, r.CredentialID, r.AuthMethod)
	switch {
	case err != nil:
		log.Printf("[resources] record[%d] request_id=%q destination=%q FAILED: %v", idx, r.RequestID, r.Destination, err)
	case n == 0:
		log.Printf("[resources] record[%d] request_id=%q destination=%q no interaction yet, will record when it lands", idx, r.RequestID, r.Destination)
	default:
		log.Printf("[resources] record[%d] request_id=%q destination=%q credential_id=%q recorded", idx, r.RequestID, r.Destination, r.CredentialID)
	}
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
	// Position is the hop's depth in the run and Branch its branch letter
	// ("" on the trunk), so two branches can share a Position. The order of
	// the list itself is the walk order (see interactionOrder).
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
		log.Printf("[auth-evidence] serve: intent=%s fetch FAILED: %v", intentID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch auth evidence: %v", err)})
		return
	}
	logEvidenceForIntent("serve", intentID, interactions, byRequest)

	hops := buildIntentAuthEvidence(interactions, byRequest)
	log.Printf("[auth-evidence] serve: intent=%s responding with %d of %d interaction(s)", intentID, len(hops), len(interactions))
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"intentID":          intentID,
		"totalInteractions": len(interactions),
		"count":             len(hops),
		"interactions":      hops,
	}})
}

// logEvidenceForIntent logs, per interaction, which evidence rows matched its
// signature and the credential fields each row carries, so a null in a
// response can be traced to the row (or the missing row) behind it.
func logEvidenceForIntent(tag, intentID string, interactions []*db.InteractionRecord, byRequest map[string][]*db.AuthEvidenceRecord) {
	rows := 0
	for _, recs := range byRequest {
		rows += len(recs)
	}
	log.Printf("[auth-evidence] %s: intent=%s interactions=%d matched_requests=%d evidence_rows=%d",
		tag, intentID, len(interactions), len(byRequest), rows)

	for _, i := range interactions {
		recs := byRequest[i.Signature]
		if i.Signature == "" {
			log.Printf("[auth-evidence] %s: intent=%s interaction=%s has NO signature, nothing can match", tag, intentID, i.InteractionID)
			continue
		}
		if len(recs) == 0 {
			log.Printf("[auth-evidence] %s: intent=%s interaction=%s signature=%s no evidence rows", tag, intentID, i.InteractionID, i.Signature)
			continue
		}
		for _, r := range recs {
			log.Printf("[auth-evidence] %s: intent=%s interaction=%s source=%q auth_method=%q credential_id=%q identity_id=%s auth_status=%q key_version=%q destination=%q observed_at=%s",
				tag, intentID, i.InteractionID, r.Source, r.AuthMethod, r.CredentialID, logStrPtr(r.IdentityID),
				r.AuthStatus, r.KeyVersion, r.Destination, logFloatPtr(r.ObservedAt))
		}
	}
}

// logStrPtr and logFloatPtr print a nil pointer as NULL, so a stored NULL is
// told apart from an empty value in the logs.
func logStrPtr(p *string) string {
	if p == nil {
		return "NULL"
	}
	return fmt.Sprintf("%q", *p)
}

func logFloatPtr(p *float64) string {
	if p == nil {
		return "NULL"
	}
	return fmt.Sprintf("%f", *p)
}
