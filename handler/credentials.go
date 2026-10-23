package handler

import (
	"database/sql"
	"fmt"
	"net/http"

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
	}
}

// CredentialsList handles GET /dashboard/v1/credentials-list?page=&pageSize=:
// every credential seen in auth evidence, most recently used first.
func (h *Handler) CredentialsList(c *gin.Context) {
	page, pageSize := listPage(c, "page", "pageSize")

	total, err := h.db.CountCredentials()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count credentials: %v", err)})
		return
	}
	credentials, err := h.db.ListCredentials(pageSize, (page-1)*pageSize)
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
