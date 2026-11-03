package handler

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"agentdna-ratelimit-auth/db"
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

// CoreRegisterUser is called by the external server to add a DID to the user
// identified by their API key. A user may hold several DIDs; the newest one
// becomes their primary DID. A DID already held by another user returns 409.
// The user is also registered with the admin server (POST /agent-admin/v1/users)
// atomically: if the admin server rejects it, the DID is not stored locally.
// POST /core/v1/register-user
// Header: X-API-Key: <api_key>
// Body:   {"user_id": "did:rubix:xyz"}
func (h *Handler)CoreRegisterUser(c *gin.Context) {
	user, ok := h.userFromAPIKey(c)
	if !ok {
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[CoreRegisterUser] rejected — user_id missing email=%q", user.Email)
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "user_id is required"})
		return
	}

	// The DIDs this user already holds tell a 409 from the admin server apart:
	// the same DID again (a retry) or an extra DID for a user the admin server
	// already has (its POST /users only takes a user's first user ID).
	existingDIDs, err := h.db.GetUserDIDsByDID(user.DID)
	if err != nil {
		log.Printf("[CoreRegisterUser] loading existing DIDs email=%q did=%q failed: %v", user.Email, user.DID, err)
	}
	alreadyHeld := false
	for _, d := range existingDIDs {
		if d == req.UserID {
			alreadyHeld = true
			break
		}
	}
	log.Printf("[CoreRegisterUser] request user_id=%q email=%q current_did=%q existing_dids=%v already_held=%t first_did=%t",
		req.UserID, user.Email, user.DID, existingDIDs, alreadyHeld, len(existingDIDs) == 0)

	// The admin server registration runs inside the local transaction, after the
	// local writes succeed and before they commit, so the DID is only kept
	// locally when the admin server accepted the user too.
	registerWithAdmin := func(email string) error {
		log.Printf("[CoreRegisterUser] local DID write ok, registering with admin server user_id=%q email=%q", req.UserID, email)
		return h.callRegisterUser(req.UserID, email, user.APIKey)
	}
	if err := h.db.AddUserDIDByAPIKey(user.APIKey, req.UserID, registerWithAdmin); err != nil {
		if errors.Is(err, db.ErrDIDTaken) {
			log.Printf("[CoreRegisterUser] 409 DID held by another user user_id=%q email=%q", req.UserID, user.Email)
			c.JSON(http.StatusConflict, Response{Status: false, Message: "this DID is already registered to another user"})
			return
		}
		var rejected *adminRejectedError
		if errors.As(err, &rejected) {
			reason := "new DID for a user with none"
			switch {
			case alreadyHeld:
				reason = "same DID registered again (retry?)"
			case len(existingDIDs) > 0:
				reason = fmt.Sprintf("additional DID — user already has %d, admin server only accepts the first", len(existingDIDs))
			}
			log.Printf("[CoreRegisterUser] 409 admin server rejected user_id=%q email=%q reason=%q admin_message=%q",
				req.UserID, user.Email, reason, rejected.message)
			c.JSON(http.StatusConflict, Response{Status: false, Message: rejected.message})
			return
		}
		log.Printf("[CoreRegisterUser] 500 user_id=%q email=%q err=%v", req.UserID, user.Email, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to add user DID: %v", err)})
		return
	}

	log.Printf("[CoreRegisterUser] registered user_id=%q email=%q", req.UserID, user.Email)
	c.JSON(http.StatusOK, Response{Status: true, Message: ""})
}

// CoreDIDByEmail resolves the DID linked to an org user's email. Called by the
// Identity Binding Service during human login to bind a run to a DID. A missing
// email, unknown user, or unlinked DID all return an empty did (fail closed) —
// the caller denies when no DID comes back.
// GET /core/v1/did-by-email?email=<email>
func (h *Handler) CoreDIDByEmail(c *gin.Context) {
	email := strings.TrimSpace(c.Query("email"))
	if email == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email query parameter is required"})
		return
	}

	did := ""
	if u, err := h.db.GetOrgUserByEmail(email); err == nil && u.DID != "" && u.DID != "none" {
		did = u.DID
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"did": did}})
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


