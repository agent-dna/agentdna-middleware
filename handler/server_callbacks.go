package handler

import (
	"fmt"
	"io"
	"net/http"

	"agentdna-ratelimit-auth/email"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// apiKeyFromHeader extracts and validates X-API-Key, returning the user record.
func (h *Handler) userFromAPIKey(c *gin.Context) (*userFromAPIKeyResult, bool) {
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "X-API-Key header is required"})
		return nil, false
	}
	user, err := h.db.GetOrgUserByAPIKey(apiKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid API key"})
		return nil, false
	}
	return &userFromAPIKeyResult{
		APIKey: apiKey,
		OrgID:  user.OrganizationID,
		DID:    user.DID,
		Name:   user.Name,
		Email:  user.Email,
	}, true
}

type userFromAPIKeyResult struct {
	APIKey string
	OrgID  string
	DID    string
	Name   string
	Email  string
}

// CoreRegisterUser is called by the external server to set the DID for a user
// identified by their API key.
// POST /core/v1/register-user
// Header: X-API-Key: <api_key>
// Body:   {"user_id": "did:rubix:xyz"}
func (h *Handler) CoreRegisterUser(c *gin.Context) {
	user, ok := h.userFromAPIKey(c)
	if !ok {
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "user_id is required"})
		return
	}

	if err := h.db.UpdateUserDIDByAPIKey(user.APIKey, req.UserID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update user DID: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Message: ""})
}

// CoreRegisterAgent is called by the external server to create an agent
// creation request on behalf of the user identified by their API key.
// POST /core/v1/register-agent
// Header: X-API-Key: <api_key>
// Body:   multipart/form-data — agent_name, agent_id, policy (file)
func (h *Handler) CoreRegisterAgent(c *gin.Context) {
	user, ok := h.userFromAPIKey(c)
	if !ok {
		return
	}

	agentName := c.PostForm("agent_name")
	agentID := c.PostForm("agent_id")

	if agentName == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agent_name is required"})
		return
	}

	policy := ""
	if fh, err := c.FormFile("policy"); err == nil {
		f, err := fh.Open()
		if err == nil {
			defer f.Close()
			raw, _ := io.ReadAll(f)
			policy = string(raw)
		}
	}
	

	requestID := uuid.New().String()
	if err := h.db.CreateRequest(requestID, "deploy_agent", policy, user.DID, agentID, agentName, "", user.OrgID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create request: %v", err)})
		return
	}

	// Notify admin.
	if _, adminEmail, err := h.db.GetAdminEmailByOrgID(user.OrgID); err == nil {
		h.sendMail(email.AgentCreationRequestNew(adminEmail, agentName, user.Name, requestID))
	}

	c.JSON(http.StatusOK, Response{Status: true, Message: ""})
}
