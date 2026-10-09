package handler

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// adminHTTP is used for calls to the admin server made while a dashboard
// request waits, so a hung admin server can't hang the request.
var adminHTTP = &http.Client{Timeout: 10 * time.Second}

// AdminLogin checks an admin's credentials against the admin server — the
// only place admin passwords live — and on success opens a middleware session
// exactly like Login does for org users. The admin server's JWT is used only
// to identify the admin and is never passed to the browser.
// POST /dashboard/v1/admin-login
// Body: {"username": "...", "password": "..."}
//
// Wrong credentials answer 400, not 401: the dashboard treats any 401 as
// "session expired" and would hide the admin server's message.
func (h *Handler) AdminLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "username and password are required"})
		return
	}

	b, _ := json.Marshal(map[string]string{"username": req.Username, "password": req.Password})
	endpoint := strings.TrimRight(h.adminServiceURL, "/") + "/agent-admin/v1/login"
	resp, err := adminHTTP.Post(endpoint, "application/json", bytes.NewReader(b))
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			log.Printf("[AdminLogin] admin server timeout username=%q err=%v", req.Username, err)
			c.JSON(http.StatusGatewayTimeout, Response{Status: false, Message: "Admin server unavailable"})
			return
		}
		log.Printf("[AdminLogin] admin server unreachable username=%q err=%v", req.Username, err)
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: "Admin server unavailable"})
		return
	}
	defer resp.Body.Close()

	var adminResp struct {
		Status  bool            `json:"status"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(raw, &adminResp); err != nil {
		log.Printf("[AdminLogin] unparseable admin server reply status=%d username=%q", resp.StatusCode, req.Username)
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: "Admin server unavailable"})
		return
	}
	if !adminResp.Status {
		msg := adminResp.Message
		if msg == "" {
			msg = "Invalid username or password"
		}
		log.Printf("[AdminLogin] rejected by admin server username=%q", req.Username)
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: msg})
		return
	}

	// The token came straight from the admin server over our own call, so its
	// claims are trusted without verifying the signature.
	var token string
	_ = json.Unmarshal(adminResp.Data, &token)
	claims := adminTokenClaims(token)

	admin, err := h.findOrCreateAdmin(req.Username, claims)
	if errors.Is(err, errAdminNotAllowed) {
		log.Printf("[AdminLogin] admin server accepted username=%q (did=%q org=%q) but refused here: %v", req.Username, claims.DID, claims.OrgID, err)
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin account is not registered with this dashboard"})
		return
	}
	if err != nil {
		log.Printf("[AdminLogin] loading admin row failed username=%q did=%q err=%v", req.Username, claims.DID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to load admin account"})
		return
	}
	// The admin server just confirmed this username for this DID. Store it
	// (rows from scripts/add_admin.py have none, older rows may hold a stale
	// display name) so /update-password addresses this admin there.
	if admin.Name != req.Username {
		if err := h.db.SetAdminName(admin.DID, req.Username); err != nil {
			log.Printf("[AdminLogin] saving username for did=%q failed: %v", admin.DID, err)
		}
		admin.Name = req.Username
	}

	if err := h.startSession(c, db.SessionAccountAdmin, admin.DID); err != nil {
		log.Printf("[AdminLogin] create session failed did=%q err=%v", admin.DID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to create session"})
		return
	}
	log.Printf("[AdminLogin] admin login success username=%q did=%q", req.Username, admin.DID)
	c.JSON(http.StatusOK, Response{
		Status:  true,
		Message: adminResp.Message,
		Data: gin.H{
			"username": admin.Name,
			"did":      admin.DID,
			"email":    admin.Email,
			"org_id":   admin.OrganizationID,
			"api_key":  admin.APIKey,
			"is_admin": true,
		},
	})
}

// errAdminNotAllowed: the admin server accepted the login, but this dashboard
// won't admit the admin (no DID in the token, or another org's admin).
var errAdminNotAllowed = errors.New("admin not allowed on this dashboard")

// findOrCreateAdmin maps an admin-server login to its new_admins row by the
// token's did claim. The admin server is the source of truth for admins, so
// an admin with no row yet gets one on first login — but only an admin of
// this middleware's org, since the admin server holds several orgs' admins.
func (h *Handler) findOrCreateAdmin(username string, cl adminClaims) (*db.AdminRecord, error) {
	if cl.DID == "" {
		return nil, fmt.Errorf("%w: token has no did claim", errAdminNotAllowed)
	}
	a, err := h.db.GetAdminByDID(cl.DID)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(cl.OrgID), strings.TrimSpace(h.orgID)) {
		return nil, fmt.Errorf("%w: admin org %q is not this dashboard's org %q", errAdminNotAllowed, cl.OrgID, h.orgID)
	}
	if err := h.db.EnsureAdmin(cl.DID, h.orgID, uuid.New().String(), username); err != nil {
		return nil, err
	}
	log.Printf("[AdminLogin] created new_admins row on first login username=%q did=%q org=%q", username, cl.DID, h.orgID)
	return h.db.GetAdminByDID(cl.DID)
}

type adminClaims struct {
	Sub   string `json:"sub"`
	DID   string `json:"did"`
	OrgID string `json:"org_id"`
}

// adminTokenClaims reads the payload of the admin server's JWT. A token that
// can't be read yields empty claims, and the login is refused.
func adminTokenClaims(token string) adminClaims {
	var cl adminClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return cl
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return cl
	}
	_ = json.Unmarshal(payload, &cl)
	return cl
}
