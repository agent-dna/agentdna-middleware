package handler

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"agentdna-ratelimit-auth/db"

	"github.com/gin-gonic/gin"
)

// timeOrNil renders a nullable timestamp as JSON null when unset.
func timeOrNil(t sql.NullTime) any {
	if t.Valid {
		return t.Time
	}
	return nil
}

func credentialSummaryJSON(c *db.CredentialSummary) gin.H {
	sources := c.Sources
	if sources == nil {
		sources = []string{}
	}
	return gin.H{
		"credentialID": c.CredentialID,
		"authMethod":   c.AuthMethod,
		"identityID":   c.IdentityID,
		"sources":      sources,
		"requestCount": c.RequestCount,
		"intentCount":  c.IntentCount,
		"userCount":    c.UserCount,
		"agentCount":   c.AgentCount,
		"toolCount":    c.ToolCount,
		"firstUsedAt":  timeOrNil(c.FirstUsedAt),
		"lastUsedAt":   timeOrNil(c.LastUsedAt),
		"status":       credentialStatusJSON(&c.CredentialStatus),
	}
}

// presentedCredentialsJSON renders a page of the credentials a user or agent
// presented, in the section shape the account and agent pages use.
func presentedCredentialsJSON(list []*db.PresentedCredential, total, page, pageSize int) gin.H {
	items := make([]gin.H, 0, len(list))
	for _, cr := range list {
		sources := cr.Sources
		if sources == nil {
			sources = []string{}
		}
		items = append(items, gin.H{
			"credentialID": cr.CredentialID,
			"authMethod":   cr.AuthMethod,
			"sources":      sources,
			"requestCount": cr.RequestCount,
			"intentCount":  cr.IntentCount,
			"firstUsedAt":  timeOrNil(cr.FirstUsedAt),
			"lastUsedAt":   timeOrNil(cr.LastUsedAt),
			"status":       credentialStatusJSON(&cr.CredentialStatus),
		})
	}
	data := pageInfo(total, page, pageSize)
	data["list"] = items
	return data
}

func credentialStatusJSON(cs *db.CredentialStatus) gin.H {
	return gin.H{
		"value":     cs.Status,
		"reason":    cs.StatusReason,
		"updatedBy": cs.StatusUpdatedBy,
		"updatedAt": timeOrNil(cs.StatusUpdatedAt),
	}
}

// CredentialsList handles GET /dashboard/v1/credentials-list?page=&pageSize=
// &status=: every credential seen in auth evidence, most recently used first.
// status (active, flagged, compromised) is optional and narrows the list.
func (h *Handler) CredentialsList(c *gin.Context) {
	status := c.Query("status")
	if status != "" && !db.ValidCredentialStatuses[status] {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "status must be one of active, flagged, compromised"})
		return
	}
	page, pageSize := listPage(c, "page", "pageSize")

	total, err := h.db.CountCredentials(status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count credentials: %v", err)})
		return
	}
	credentials, err := h.db.ListCredentials(status, pageSize, (page-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch credentials: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(credentials))
	for _, cr := range credentials {
		list = append(list, credentialSummaryJSON(cr))
	}
	data := pageInfo(total, page, pageSize)
	data["credentialsList"] = list
	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

// CredentialInfo handles GET /dashboard/v1/credential-info?credentialID=
// &intentsPage=&intentsPageSize=: one credential, a page of the intents it was
// used in, and every user, agent and tool that presented it.
func (h *Handler) CredentialInfo(c *gin.Context) {
	credentialID := c.Query("credentialID")
	if credentialID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "credentialID is required"})
		return
	}

	credential, err := h.db.GetCredential(credentialID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch credential: %v", err)})
		return
	}
	if credential == nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "credential not found"})
		return
	}

	intentsPage, intentsPageSize := listPage(c, "intentsPage", "intentsPageSize")
	intents, err := h.db.GetCredentialIntents(credentialID, intentsPageSize, (intentsPage-1)*intentsPageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch credential intents: %v", err)})
		return
	}
	actors, err := h.db.GetCredentialActors(credentialID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch credential users: %v", err)})
		return
	}

	intentList := make([]gin.H, 0, len(intents))
	for _, i := range intents {
		intentList = append(intentList, gin.H{
			"intentID":       i.IntentID,
			"initiatorDID":   i.InitiatorDID,
			"initiatorName":  i.InitiatorName,
			"status":         i.Status,
			"reviewStatus":   i.ReviewStatus,
			"threatDetected": i.ThreatDetected,
			"startedAt":      timeOrNil(i.StartedAt),
			"requestCount":   i.RequestCount,
			"lastUsedAt":     timeOrNil(i.LastUsedAt),
		})
	}
	byType := map[string][]gin.H{"user": {}, "agent": {}, "tool": {}, "unknown": {}}
	for _, a := range actors {
		byType[a.Type] = append(byType[a.Type], gin.H{
			"did":          a.DID,
			"name":         a.Name,
			"requestCount": a.RequestCount,
			"intentCount":  a.IntentCount,
			"lastUsedAt":   timeOrNil(a.LastUsedAt),
		})
	}

	intentsData := pageInfo(credential.IntentCount, intentsPage, intentsPageSize)
	intentsData["list"] = intentList
	data := credentialSummaryJSON(credential)
	data["intents"] = intentsData
	data["users"] = byType["user"]
	data["agents"] = byType["agent"]
	data["tools"] = byType["tool"]
	data["unknown"] = byType["unknown"]
	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

const maxCredentialStatusReason = 1000

// UpdateCredentialStatus handles POST /dashboard/v1/update-credential-status
// {credentialID, status, reason}: sets a credential's status. Admins only.
func (h *Handler) UpdateCredentialStatus(c *gin.Context) {
	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		CredentialID string `json:"credentialID"`
		Status       string `json:"status"`
		Reason       string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid request body"})
		return
	}
	req.CredentialID = strings.TrimSpace(req.CredentialID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.CredentialID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "credentialID is required"})
		return
	}
	if !db.ValidCredentialStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "status must be one of active, flagged, compromised"})
		return
	}
	if len(req.Reason) > maxCredentialStatusReason {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: fmt.Sprintf("reason must be at most %d characters", maxCredentialStatusReason)})
		return
	}

	observed, err := h.db.CredentialObserved(req.CredentialID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to look up credential: %v", err)})
		return
	}
	if !observed {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "credential not found"})
		return
	}

	updatedBy := c.GetString(CtxEmail)
	if updatedBy == "" {
		updatedBy = c.GetString(CtxDID)
	}
	cs, err := h.db.SetCredentialStatus(req.CredentialID, req.Status, req.Reason, updatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update credential status: %v", err)})
		return
	}
	log.Printf("[credentials] status credential_id=%q status=%s by=%q reason=%q", req.CredentialID, cs.Status, updatedBy, cs.StatusReason)

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"credentialID": req.CredentialID,
		"status":       credentialStatusJSON(cs),
	}})
}
