package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/handler"
	"agentdna-ratelimit-auth/router"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

func initConfig() (string, *url.URL, string, handler.SessionConfig, string, string, string, string, string) {
	dsn := os.Getenv("DATABASE_URL")
	backendURLStr := os.Getenv("RUBIX_NODE_URL")
	serverPort := os.Getenv("SERVER_PORT")
	session := sessionConfigFromEnv()
	orgID := os.Getenv("ORG_ID")
	adminServiceURL := os.Getenv("ADMIN_SERVICE_URL")
	cbacServiceURL := os.Getenv("CBAC_SERVICE_URL")
	createAgentEndpoint := os.Getenv("CREATE_AGENT_ENDPOINT")
	updateAgentEndpoint := os.Getenv("UPDATE_AGENT_ENDPOINT")

	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	if backendURLStr == "" {
		log.Fatal("RUBIX_NODE_URL environment variable is required")
	}
	if serverPort == "" {
		log.Fatal("SERVER_PORT environment variable is required")
	}
	if orgID == "" {
		log.Fatal("ORG_ID environment variable is required")
	}

	parsedURL, err := url.Parse(backendURLStr)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		log.Fatalf("RUBIX_NODE_URL invalid format: %s", backendURLStr)
	}

	return dsn, parsedURL, serverPort, session, orgID, adminServiceURL, cbacServiceURL, createAgentEndpoint, updateAgentEndpoint
}

// sessionConfigFromEnv reads the dashboard session cookie settings:
//
//	CORS_ALLOWED_ORIGINS     comma-separated dashboard origins, e.g.
//	                         "https://app.agentdna.io,http://localhost:3000"
//	SESSION_COOKIE_SAMESITE  lax (default) | strict | none — use none only when
//	                         the dashboard and API are on different sites
//	SESSION_COOKIE_SECURE    true (default) | false — false only for plain-http dev
//	SESSION_COOKIE_DOMAIN    optional cookie Domain attribute
func sessionConfigFromEnv() handler.SessionConfig {
	cfg := handler.SessionConfig{
		CookieSecure:   os.Getenv("SESSION_COOKIE_SECURE") != "false",
		CookieSameSite: http.SameSiteLaxMode,
		CookieDomain:   os.Getenv("SESSION_COOKIE_DOMAIN"),
		AllowedOrigins: handler.TrimOrigins(os.Getenv("CORS_ALLOWED_ORIGINS")),
	}
	switch strings.ToLower(os.Getenv("SESSION_COOKIE_SAMESITE")) {
	case "", "lax":
	case "strict":
		cfg.CookieSameSite = http.SameSiteStrictMode
	case "none":
		cfg.CookieSameSite = http.SameSiteNoneMode
		if !cfg.CookieSecure {
			log.Fatal("SESSION_COOKIE_SAMESITE=none requires SESSION_COOKIE_SECURE=true (browsers drop the cookie otherwise)")
		}
	default:
		log.Fatalf("SESSION_COOKIE_SAMESITE must be lax, strict or none, got %q", os.Getenv("SESSION_COOKIE_SAMESITE"))
	}
	if len(cfg.AllowedOrigins) == 0 {
		log.Printf("[session] CORS_ALLOWED_ORIGINS is empty — only a dashboard served from the API's own origin can log in")
	}
	return cfg
}

func main() {
	dsn, backendURL, serverPort, session, orgID, adminServiceURL, cbacServiceURL, createAgentEndpoint, updateAgentEndpoint := initConfig()

	database := db.New(dsn)
	defer database.Close()

	h := handler.New(database, backendURL, session, orgID, adminServiceURL, cbacServiceURL, createAgentEndpoint, updateAgentEndpoint)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(h.CORSMiddleware())

	router.Register(r, h)

	api := r.Group("/rubix")
	api.Any("/*path", h.ProxyHandler)

	log.Printf("Starting on :%s", serverPort)
	r.Run(":" + serverPort)
}
