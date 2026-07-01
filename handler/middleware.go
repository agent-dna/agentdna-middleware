package handler

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	CtxDID     = "jwt_did"
	CtxEmail   = "jwt_email"
	CtxOrgID   = "jwt_org_id"
	CtxNFTID   = "jwt_nft_id"
	CtxAPIKey  = "jwt_api_key"
	CtxIsAdmin = "jwt_is_admin"
)

func (h *Handler) JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "missing or invalid authorization header"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		log.Printf("[JWT] verifying token for %s %s", c.Request.Method, c.Request.URL.Path)

		// Decode without verification to log raw payload for debugging.
		rawToken, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
		if rawClaims, ok := rawToken.Claims.(jwt.MapClaims); ok {
			log.Printf("[JWT] raw payload: %v", rawClaims)
		} else {
			log.Printf("[JWT] could not parse raw payload: %v", err)
		}

		claims := &JWTClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(h.jwtSecret), nil
		})

		if claims.IssuedAt != nil {
			log.Printf("[JWT] issued_at=%s", claims.IssuedAt.Time.Format("2006-01-02 15:04:05"))
		}
		if claims.ExpiresAt != nil {
			log.Printf("[JWT] expires_at=%s (in %s)", claims.ExpiresAt.Time.Format("2006-01-02 15:04:05"), time.Until(claims.ExpiresAt.Time).Round(time.Second))
		}

		if err != nil || !token.Valid {
			log.Printf("[JWT] verification failed: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid or expired token"})
			return
		}

		// Always verify admin status from the DB — never trust the token claim.
		isAdmin := false
		log.Printf("[JWT:admin-check] did=%q email=%q org_id=%q", claims.DID, claims.Email, claims.OrgID)
		if claims.DID != "" {
			_, err := h.db.GetAdminByDID(claims.DID)
			log.Printf("[JWT:admin-check] GetAdminByDID did=%q err=%v", claims.DID, err)
			if err == nil {
				isAdmin = true
			}
		}
		if !isAdmin && claims.Email != "" {
			_, err := h.db.GetAdminByEmail(claims.Email)
			log.Printf("[JWT:admin-check] GetAdminByEmail email=%q err=%v", claims.Email, err)
			if err == nil {
				isAdmin = true
			}
		}
		// Fallback: check by org_id — if an admin record exists and DID matches, it's admin.
		if !isAdmin && h.orgID != "" {
			admin, err := h.db.GetAdminByOrgID(h.orgID)
			log.Printf("[JWT:admin-check] GetAdminByOrgID org_id=%q foundDID=%q err=%v", h.orgID, func() string {
				if admin != nil {
					return admin.DID
				}
				return ""
			}(), err)
			if err == nil && admin.DID == claims.DID {
				isAdmin = true
			}
		}
		log.Printf("[JWT:admin-check] result is_admin=%v", isAdmin)

		log.Printf("[JWT] verified ok — sub=%s did=%s org_id=%s is_admin=%v", claims.Subject, claims.DID, h.orgID, isAdmin)

		c.Set(CtxDID, claims.DID)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxOrgID, h.orgID)
		c.Set(CtxNFTID, claims.NFTID)
		c.Set(CtxAPIKey, claims.APIKey)
		c.Set(CtxIsAdmin, isAdmin)
		c.Next()
	}
}
