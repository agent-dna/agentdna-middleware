package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"
	"github.com/gin-gonic/gin"
)

// Values the session middleware puts on the gin context for handlers.
const (
	CtxDID         = "auth_did"
	CtxEmail       = "auth_email"
	CtxOrgID       = "auth_org_id"
	CtxNFTID       = "auth_nft_id"
	CtxAPIKey      = "auth_api_key"
	CtxIsAdmin     = "auth_is_admin"
	CtxSessionHash = "auth_session_hash"
	// CtxAccountType is db.SessionAccountUser or db.SessionAccountAdmin: the
	// table the logged-in account lives in (an org user can still be IsAdmin).
	CtxAccountType = "auth_account_type"
	// CtxAccountID is that account's primary key: email for users, DID for admins.
	CtxAccountID = "auth_account_id"
	// CtxName is the account's display name; for admins it is also their
	// admin server username.
	CtxName = "auth_name"
)

const (
	SessionCookieName = "agentdna_session"
	sessionTTL        = 7 * 24 * time.Hour
)

// SessionConfig controls the session cookie and which browser origins may
// call the dashboard API with it.
type SessionConfig struct {
	// CookieSecure sends the cookie over HTTPS only. Leave on everywhere
	// except plain-http local development.
	CookieSecure bool
	// CookieSameSite is Lax when the dashboard and API share a site, None
	// when they live on different sites (None requires CookieSecure).
	CookieSameSite http.SameSite
	// CookieDomain is optional; empty means "the API host only".
	CookieDomain string
	// AllowedOrigins are the exact dashboard origins (scheme://host[:port])
	// allowed to make credentialed requests. Empty means same-origin only.
	AllowedOrigins []string
}

// newSessionToken returns a random 256-bit token (sent to the browser) and
// its SHA-256 hex hash (stored in the DB).
func newSessionToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashSessionToken(token), nil
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) setSessionCookie(c *gin.Context, token string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Domain:   h.session.CookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.session.CookieSecure,
		SameSite: h.session.CookieSameSite,
	})
}

func (h *Handler) clearSessionCookie(c *gin.Context) {
	h.setSessionCookie(c, "", -1)
}

// startSession creates a session row for the account and sets the cookie.
// accountID is the user's email or the admin's DID (see db.SessionRecord).
func (h *Handler) startSession(c *gin.Context, accountType, accountID string) error {
	if err := h.db.DeleteExpiredSessions(); err != nil {
		log.Printf("[session] cleanup of expired sessions failed: %v", err)
	}
	token, hash, err := newSessionToken()
	if err != nil {
		return err
	}
	if err := h.db.CreateSession(hash, accountType, accountID, c.ClientIP(), c.Request.UserAgent(), time.Now().Add(sessionTTL)); err != nil {
		return err
	}
	h.setSessionCookie(c, token, int(sessionTTL.Seconds()))
	return nil
}

// originAllowed reports whether a browser Origin may make credentialed
// requests: it is in AllowedOrigins, or it is the API's own origin.
func (h *Handler) originAllowed(origin, host string) bool {
	for _, o := range h.session.AllowedOrigins {
		if origin == o {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == host
}

// CORSMiddleware lets the listed dashboard origins call the API with cookies.
// Browsers refuse credentialed requests under "Access-Control-Allow-Origin: *",
// so the allowed origin is echoed back instead. Server-to-server callers
// (X-API-Key, agent SDK) send no Origin and are unaffected.
func (h *Handler) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		c.Header("Vary", "Origin")
		if origin != "" && h.originAllowed(origin, c.Request.Host) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		} else if origin != "" {
			// Unknown site: allow non-credentialed calls only, as before.
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		c.Header("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-API-Key, X-Agent-Description, X-Agent-Repo")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// SessionAuthMiddleware authenticates dashboard requests by the session
// cookie and loads the account's current data from the DB, so a new DID or
// email takes effect on the very next request.
func (h *Handler) SessionAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// CSRF guard: with a cookie the browser authenticates for us, so a
		// state-changing request must come from an allowed dashboard origin.
		if m := c.Request.Method; m != http.MethodGet && m != http.MethodHead {
			if origin := c.GetHeader("Origin"); origin != "" && !h.originAllowed(origin, c.Request.Host) {
				log.Printf("[session] rejected %s %s from origin=%q", m, c.Request.URL.Path, origin)
				c.AbortWithStatusJSON(http.StatusForbidden, Response{Status: false, Message: "origin not allowed"})
				return
			}
		}

		token, err := c.Cookie(SessionCookieName)
		if err != nil || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "not logged in"})
			return
		}
		hash := hashSessionToken(token)
		sess, err := h.db.GetActiveSession(hash)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				h.sessionCheckFailed(c, "session lookup", err)
				return
			}
			h.clearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "session expired or invalid"})
			return
		}

		var did, email, name, nftID, apiKey string
		isAdmin := false
		switch sess.AccountType {
		case db.SessionAccountAdmin:
			admin, err := h.db.GetAdminByDID(sess.AccountID)
			if err != nil {
				h.rejectSession(c, hash, "admin account not found", err)
				return
			}
			did, email, name, apiKey, isAdmin = admin.DID, admin.Email, admin.Name, admin.APIKey, true
		default:
			user, err := h.db.GetOrgUserByEmail(sess.AccountID)
			if err != nil {
				h.rejectSession(c, hash, "user account not found", err)
				return
			}
			did, email, name, nftID, apiKey = user.DID, user.Email, user.Name, user.NFTID, user.APIKey
			// An org user who is also registered as an admin (same email or
			// DID) gets admin rights, as under the previous JWT check.
			if _, err := h.db.GetAdminByEmail(email); err == nil {
				isAdmin = true
			} else if did != "" && did != "none" {
				if _, err := h.db.GetAdminByDID(did); err == nil {
					isAdmin = true
				}
			}
		}

		if err := h.db.TouchSession(hash); err != nil {
			log.Printf("[session] touch failed: %v", err)
		}

		c.Set(CtxDID, did)
		c.Set(CtxEmail, email)
		c.Set(CtxName, name)
		c.Set(CtxOrgID, h.orgID)
		c.Set(CtxNFTID, nftID)
		c.Set(CtxAPIKey, apiKey)
		c.Set(CtxIsAdmin, isAdmin)
		c.Set(CtxSessionHash, hash)
		c.Set(CtxAccountType, sess.AccountType)
		c.Set(CtxAccountID, sess.AccountID)
		c.Next()
	}
}

// rejectSession ends a session whose account no longer exists.
func (h *Handler) rejectSession(c *gin.Context, hash, reason string, err error) {
	if !errors.Is(err, sql.ErrNoRows) {
		h.sessionCheckFailed(c, reason, err)
		return
	}
	log.Printf("[session] %s: %v", reason, err)
	_ = h.db.DeleteSession(hash)
	h.clearSessionCookie(c)
	c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "session expired or invalid"})
}

// sessionCheckFailed answers a request whose session couldn't be checked
// because the database errored (timeout, dropped connection): 503, with the
// session row and cookie kept, so a brief outage doesn't log anyone out.
func (h *Handler) sessionCheckFailed(c *gin.Context, what string, err error) {
	log.Printf("[session] %s failed, keeping the session: %v", what, err)
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, Response{Status: false, Message: "temporarily unable to verify your session, try again"})
}

// Logout ends the caller's current session.
// POST /dashboard/v1/logout
func (h *Handler) Logout(c *gin.Context) {
	if err := h.db.DeleteSession(c.GetString(CtxSessionHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to log out"})
		return
	}
	h.clearSessionCookie(c)
	c.JSON(http.StatusOK, Response{Status: true, Message: "logged out"})
}

// LogoutAll ends every session of the caller's account, on every device,
// including the current one.
// POST /dashboard/v1/logout-all
func (h *Handler) LogoutAll(c *gin.Context) {
	n, err := h.db.DeleteAccountSessions(c.GetString(CtxAccountType), c.GetString(CtxAccountID), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to log out"})
		return
	}
	h.clearSessionCookie(c)
	c.JSON(http.StatusOK, Response{Status: true, Message: "logged out of all sessions", Data: gin.H{"sessionsEnded": n}})
}

// Session tells the dashboard whether it is logged in and as whom — the
// cookie is HttpOnly, so the frontend cannot read it itself.
// GET /dashboard/v1/session
func (h *Handler) Session(c *gin.Context) {
	sess, err := h.db.GetActiveSession(c.GetString(CtxSessionHash))
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "session expired or invalid"})
		return
	}
	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"email":     c.GetString(CtxEmail),
			"name":      c.GetString(CtxName),
			"did":       c.GetString(CtxDID),
			"org_id":    c.GetString(CtxOrgID),
			"is_admin":  c.GetBool(CtxIsAdmin),
			"expiresAt": sess.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// endOtherSessions revokes every session of an account except the caller's
// current one (empty keepHash ends them all). Used after password changes.
func (h *Handler) endOtherSessions(accountType, accountID, keepHash string) {
	n, err := h.db.DeleteAccountSessions(accountType, accountID, keepHash)
	if err != nil {
		log.Printf("[session] revoke sessions type=%s account=%q failed: %v", accountType, accountID, err)
		return
	}
	log.Printf("[session] revoked %d session(s) type=%s account=%q", n, accountType, accountID)
}

// TrimOrigins parses a comma-separated origin list, dropping blanks and any
// trailing slash so "https://app.example.com/" matches the browser's Origin.
func TrimOrigins(raw string) []string {
	var out []string
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			out = append(out, o)
		}
	}
	return out
}
