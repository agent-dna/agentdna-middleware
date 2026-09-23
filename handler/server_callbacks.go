package handler

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"agentdna-ratelimit-auth/email"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// apiKeyFromHeader extracts and validates X-API-Key, returning the user record.
func (h *Handler) userFromAPIKey(c *gin.Context) (*userFromAPIKeyResult, bool) {
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		log.Printf("[userFromAPIKey] rejected — missing X-API-Key header path=%s", c.Request.URL.Path)
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "X-API-Key header is required"})
		return nil, false
	}
	log.Printf("[userFromAPIKey] looking up api_key=%q path=%s", apiKey, c.Request.URL.Path)
	user, err := h.db.GetOrgUserByAPIKey(apiKey)
	if err != nil {
		log.Printf("[userFromAPIKey] no user found for api_key=%q path=%s err=%v", apiKey, c.Request.URL.Path, err)
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid API key"})
		return nil, false
	}
	log.Printf("[userFromAPIKey] resolved api_key=%q -> did=%q email=%q name=%q org_id=%q", apiKey, user.DID, user.Email, user.Name, user.OrganizationID)
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
	log.Printf("[CoreRegisterAgent] request received api_key=%q", c.GetHeader("X-API-Key"))

	user, ok := h.userFromAPIKey(c)
	if !ok {
		log.Printf("[CoreRegisterAgent] aborting — could not resolve user from api_key")
		return
	}
	log.Printf("[CoreRegisterAgent] resolved caller did=%q email=%q org_id=%q", user.DID, user.Email, user.OrgID)

	agentName := c.PostForm("agent_name")
	agentID := c.PostForm("agent_id")
	log.Printf("[CoreRegisterAgent] form fields agent_name=%q agent_id=%q did=%q", agentName, agentID, user.DID)

	if agentName == "" {
		log.Printf("[CoreRegisterAgent] rejected — agent_name is required did=%q", user.DID)
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
	log.Printf("[CoreRegisterAgent] policy file present=%v bytes=%d did=%q", policy != "", len(policy), user.DID)

	if agentID != "" {
		if exists, err := h.db.ActiveRequestExistsForAgent(agentID); err != nil {
			log.Printf("[CoreRegisterAgent] ActiveRequestExistsForAgent check failed agentID=%q err=%v", agentID, err)
		} else if exists {
			log.Printf("[CoreRegisterAgent] duplicate request blocked agentID=%q did=%q", agentID, user.DID)
			c.JSON(http.StatusOK, Response{Status: true, Message: "duplicate id"})
			return
		}
	}

	requestID := uuid.New().String()
	log.Printf("[CoreRegisterAgent] saving request request_id=%q type=deploy_agent creator_did=%q agent_id=%q agent_name=%q org_id=%q", requestID, user.DID, agentID, agentName, user.OrgID)
	if err := h.db.CreateRequest(requestID, "deploy_agent", policy, user.DID, agentID, agentName, "", user.OrgID); err != nil {
		log.Printf("[CoreRegisterAgent] failed to save request request_id=%q creator_did=%q err=%v", requestID, user.DID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create request: %v", err)})
		return
	}
	log.Printf("[CoreRegisterAgent] request saved request_id=%q creator_did=%q agent_name=%q", requestID, user.DID, agentName)

	// Notify all admins in the org.
	adminEmails, err := h.db.GetAllAdminEmailsByOrgID(user.OrgID)
	if err != nil {
		log.Printf("[CoreRegisterAgent] GetAllAdminEmailsByOrgID failed orgID=%q err=%v", user.OrgID, err)
	} else if len(adminEmails) == 0 {
		log.Printf("[CoreRegisterAgent] no admin emails found for orgID=%q", user.OrgID)
	} else {
		log.Printf("[CoreRegisterAgent] notifying %d admin(s)=%v agentName=%q requestID=%q", len(adminEmails), adminEmails, agentName, requestID)
		for _, adminEmail := range adminEmails {
			if strings.TrimSpace(adminEmail) == "" {
				continue
			}
			h.sendMail(email.AgentCreationRequestNew(adminEmail, agentName, user.Name, requestID))
		}
	}

	c.JSON(http.StatusOK, Response{Status: true, Message: ""})
}


