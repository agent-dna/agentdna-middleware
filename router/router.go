package router

import (
	"agentdna-ratelimit-auth/handler"
	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, h *handler.Handler) {
	r.GET("/healthz", h.Healthz)

	// Dashboard — public
	r.POST("/login", h.Login)
	r.POST("/signup", h.Signup)
	r.POST("/create-admin", h.CreateAdmin)
	r.POST("/register-admin", h.RegisterAdminMiddleware)

	// CBAC authorization gate — called by the agent runtime / SDK.
	r.POST("/authorize-action", h.AuthorizeAction)

	// Dashboard — JWT protected
	dashboard := r.Group("/", h.JWTAuthMiddleware())
	dashboard.GET("/home-metrics", h.HomeMetrics)
	dashboard.GET("/interactions-list", h.InteractionsList)
	dashboard.GET("/agent-metrics", h.AgentMetrics)
	dashboard.GET("/agents-list", h.AgentsList)
	dashboard.GET("/users-list", h.UsersList)
	dashboard.GET("/search-user", h.SearchUser)
	dashboard.POST("/create-user", h.CreateUser)
	dashboard.GET("/agent-interactions", h.AgentInteractions)
	dashboard.GET("/agent-intents", h.AgentIntents)
	dashboard.GET("/user-intents", h.UserIntents)
	dashboard.GET("/agent-info", h.AgentInfo)
	dashboard.GET("/intent-info", h.IntentInfo)
	dashboard.GET("/intent-diagram", h.IntentDiagram)
	dashboard.GET("/intent-block-data", h.GetIntentBlockData)
	dashboard.GET("/tools-list", h.ToolsList)
	dashboard.GET("/tool-info", h.ToolInfo)
	dashboard.GET("/intent-list", h.IntentList)
	dashboard.GET("/threats-list", h.ThreatsList)
	dashboard.GET("/top-threat-agents", h.TopThreatAgents)

	dashboard.GET("/agents-creation-requests-list", h.AgentsCreationRequestsList)
	dashboard.GET("/agents-creation-requests-list-user", h.AgentsCreationRequestsListUser)
	dashboard.POST("/agents-creation-requests-create", h.AgentsCreationRequestsCreate)
	dashboard.POST("/agents-creation-requests-edit", h.AgentsCreationRequestsEdit)

	dashboard.POST("/agent-creation-request-result-submit", h.AgentCreationRequestSubmit)
	dashboard.POST("/agent-info-edit", h.AgentInfoEdit)

	dashboard.GET("/agent-access-requests-list-org", h.AgentAccessRequestsListOrg)
	dashboard.GET("/agent-access-requests-list-user", h.AgentAccessRequestsListUser)
	dashboard.POST("/agent-access-request-submit", h.AgentAccessRequestSubmit)

	// Policy file upload / retrieval
	dashboard.POST("/upload-user-policy", h.UploadUserPolicy)
	dashboard.GET("/user-policy", h.GetUserPolicy)
	dashboard.POST("/upload-agent-policy", h.UploadAgentPolicy)
	dashboard.GET("/agent-policy", h.GetAgentPolicy)
	dashboard.GET("/agent-policy-history", h.GetAgentPolicyHistory)
	dashboard.GET("/agent-policy-update", h.GetAgentPolicyUpdate)


}
