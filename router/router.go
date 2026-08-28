package router

import (
	"agentdna-ratelimit-auth/handler"
	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, h *handler.Handler) {
	r.GET("/healthz", h.Healthz)
	r.POST("/core/v1/register-user", h.CoreRegisterUser)
	r.POST("/core/v1/register-agent", h.CoreRegisterAgent)

	// Dashboard — public
	public := r.Group("/dashboard/v1")
	public.POST("/login", h.Login)
	public.POST("/send-otp", h.SendOTP)
	public.POST("/forgot-password", h.ForgotPassword)
	public.POST("/reset-password", h.ResetPassword)
	public.POST("/register-user", h.RegisterUser)
	public.POST("/signup", h.Signup)

	// public.POST("/create-admin", h.CreateAdmin)
	// public.POST("/register-admin", h.RegisterAdminMiddleware)

	// CBAC authorization gate — called by the agent runtime / SDK.
	public.POST("/authorize-action", h.AuthorizeAction)
	public.POST("/app-registration", h.AppRegistration)
	public.GET("/global-stats", h.GlobalStats)

	// Dashboard — JWT protected
	dashboard := r.Group("/dashboard/v1", h.JWTAuthMiddleware())
	dashboard.GET("/user-profile", h.UserProfile) 
	dashboard.GET("/admin-profile", h.AdminProfile) 

	dashboard.GET("/home-metrics", h.HomeMetrics)
	dashboard.GET("/interactions-list", h.InteractionsList)
	dashboard.GET("/agent-metrics", h.AgentMetrics) 

	dashboard.GET("/agents-list", h.AgentsList)
	dashboard.GET("/users-list", h.UsersList) 
	dashboard.POST("/create-user", h.CreateUser)
	dashboard.GET("/agent-interactions", h.AgentInteractions)
	dashboard.GET("/agent-intents", h.AgentIntents)
	dashboard.GET("/user-intents", h.UserIntents)
	dashboard.GET("/agent-info", h.AgentInfo)
	dashboard.POST("/revoke-agent", h.RevokeAgent)
	dashboard.GET("/intent-info", h.IntentInfo)
	dashboard.GET("/intent-diagram", h.IntentDiagram)
	dashboard.GET("/intent-block-data", h.GetIntentBlockData)
	dashboard.GET("/intent-raw-data", h.GetIntentRawData)
	dashboard.POST("/update-password", h.UpdatePassword)
	dashboard.POST("/update-profile", h.UpdateProfile)
	dashboard.GET("/tools-list", h.ToolsList)
	dashboard.GET("/tool-info", h.ToolInfo)
	dashboard.GET("/user-info", h.UserInfo)
	dashboard.GET("/intent-list", h.IntentList)
	dashboard.GET("/threats-list", h.ThreatsList)
	dashboard.GET("/top-threat-agents", h.TopThreatAgents)
	dashboard.GET("/interactions/series", h.InteractionSeries)
	dashboard.GET("/search", h.Search)
	dashboard.GET("/agents-apps-metrics", h.AgentsAppsMetrics)

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

