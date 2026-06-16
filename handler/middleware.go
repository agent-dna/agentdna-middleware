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

		// If is_admin is not in the JWT, fall back to a DB lookup by DID or email.
		isAdmin := claims.IsAdmin
		if !isAdmin {
			did := claims.DID
			if did == "" {
				did = claims.Subject // some servers put identity in sub
			}
			if did != "" {
				if _, err := h.db.GetAdminByDID(did); err == nil {
					isAdmin = true
					log.Printf("[JWT] is_admin not in token, confirmed admin via DB DID lookup did=%s", did)
				}
			}
			if !isAdmin && claims.Email != "" {
				if _, err := h.db.GetAdminByEmail(claims.Email); err == nil {
					isAdmin = true
					log.Printf("[JWT] is_admin not in token, confirmed admin via DB email lookup email=%s", claims.Email)
				}
			}
		}

		log.Printf("[JWT] verified ok — sub=%s did=%s org_id=%s is_admin=%v", claims.Subject, claims.DID, claims.OrgID, isAdmin)

		c.Set(CtxDID, claims.DID)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxOrgID, claims.OrgID)
		c.Set(CtxNFTID, claims.NFTID)
		c.Set(CtxAPIKey, claims.APIKey)
		c.Set(CtxIsAdmin, isAdmin)
		c.Next()
	}
}
