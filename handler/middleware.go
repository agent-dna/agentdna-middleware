package handler

import (
	"fmt"
	"net/http"
	"strings"

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

		claims := &JWTClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(h.jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid or expired token"})
			return
		}

		c.Set(CtxDID, claims.DID)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxOrgID, claims.OrgID)
		c.Set(CtxNFTID, claims.NFTID)
		c.Set(CtxAPIKey, claims.APIKey)
		c.Set(CtxIsAdmin, claims.IsAdmin)
		c.Next()
	}
}
