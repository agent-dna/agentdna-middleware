package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/handler"
	"agentdna-ratelimit-auth/router"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

func initConfig() (string, *url.URL, string, string, string, string, string, string) {
	dsn := os.Getenv("DATABASE_URL")
	backendURLStr := os.Getenv("RUBIX_NODE_URL")
	serverPort := os.Getenv("SERVER_PORT")
	jwtSecret := os.Getenv("JWT_SECRET")
	orgID := os.Getenv("ORG_ID")
	adminServiceURL := os.Getenv("ADMIN_SERVICE_URL")
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
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	if orgID == "" {
		log.Fatal("ORG_ID environment variable is required")
	}

	parsedURL, err := url.Parse(backendURLStr)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		log.Fatalf("RUBIX_NODE_URL invalid format: %s", backendURLStr)
	}

	return dsn, parsedURL, serverPort, jwtSecret, orgID, adminServiceURL, createAgentEndpoint, updateAgentEndpoint
}

func main() {
	dsn, backendURL, serverPort, jwtSecret, orgID, adminServiceURL, createAgentEndpoint, updateAgentEndpoint := initConfig()

	database := db.New(dsn)
	defer database.Close()

	h := handler.New(database, backendURL, jwtSecret, orgID, adminServiceURL, createAgentEndpoint, updateAgentEndpoint)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		c.Header("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-API-Key, X-Agent-Description, X-Agent-Repo")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	router.Register(r, h)

	api := r.Group("/rubix")
	api.Any("/*path", h.ProxyHandler)

	log.Printf("Starting on :%s", serverPort)
	r.Run(":" + serverPort)
}
