package handler

import (
	"net/http"

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
