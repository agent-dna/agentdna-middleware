package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	// Dashboard
	r.GET("/home-metrics", h.homeMetrics)
	r.GET("/interactions-list", h.interactionsList)

	// Agent metrics & listing
	r.GET("/agent-metrics", h.agentMetrics)
	r.GET("/agents-list", h.agentsList)

	// Authorization & user management
	r.GET("/users-list", h.usersList)
	r.GET("/search-user", h.searchUser)

	// Agent creation requests
	r.GET("/agents-creation-requests-list", h.agentsCreationRequestsList)
	r.GET("/agent-creation-request-edit", h.agentCreationRequestEdit)
	r.GET("/agent-creation-request-submit", h.agentCreationRequestSubmit)

	// Agent access requests
	r.GET("/agent-access-requests-list", h.agentAccessRequestsList)
	r.GET("/agent-access-request-submit", h.agentAccessRequestSubmit)

	
}

func (h *Handler) homeMetrics(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) interactionsList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentMetrics(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentsList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) usersList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) searchUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentsCreationRequestsList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentCreationRequestEdit(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentCreationRequestSubmit(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentAccessRequestsList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

func (h *Handler) agentAccessRequestSubmit(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}
