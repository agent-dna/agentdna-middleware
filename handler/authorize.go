package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// appRequest describes the downstream App call (Slack, GitHub, etc.) that the
// agent wants to make. The Python library wrapping the agent supplies this so
// the middleware can forward the comm once the admin server authorizes it.
type appRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// authorizeActionRequest is the body accepted by the AuthorizeAction endpoint.
// agent_id + action_intent go to the admin server for the CBAC decision;
// app_request (optional) is forwarded to the App when the decision is allow.
type authorizeActionRequest struct {
	AgentID      string      `json:"agent_id"`
	ActionIntent string      `json:"action_intent"`
	AppRequest   *appRequest `json:"app_request"`
	AgentEnvelope *gin.H      `json:"envelope"` // for future use: the middleware can pass the agent's
}

// AuthorizeAction is the CBAC gate that sits in the Agent -> Middleware -> App
// path. It asks the admin server whether the agent may perform the action; the
// admin server has no knowledge of the App, so the middleware itself forwards
// the comm to the App on allow and blocks it on deny.
//
//	Agent -> Middleware --(agent_id, action_intent)--> Admin Server (decision)
//	         Middleware --(app_request, if allowed)--> App
//
// Behaviour:
//   - admin server unreachable          -> 502, status:false (caller fails closed)
//   - decision = deny                   -> 403, status:false, data.authorized:false
//   - allow, no app_request supplied     -> 200, status:true, data.authorized:true
//   - allow, app_request supplied        -> the App's status code and body are relayed verbatim
func (h *Handler) AuthorizeAction(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	var req authorizeActionRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentID == "" || req.ActionIntent == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agent_id and action_intent are required"})
		return
	}
	if req.AppRequest != nil && req.AppRequest.URL == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "app_request.url is required when app_request is provided"})
		return
	}

	// agent_id is an agent DID. Resolve it to the agent's nft_id, which is the
	// identifier the admin server expects. An unknown DID is denied (fail
	// closed); a lookup failure is a fail-closed error.
	nftID, found, err := h.db.GetAgentNFTIDByDID(req.AgentID)
	if err != nil {
		c.Header("X-CBAC-Decision", "error")
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: fmt.Sprintf("agent lookup failed: %v", err)})
		return
	}
	if !found {
		c.Header("X-CBAC-Decision", "deny")
		c.JSON(http.StatusForbidden, Response{
			Status: false,
			Data:   gin.H{"authorized": false, "message": fmt.Sprintf("unknown agent_id: %q is not a registered agent", req.AgentID)},
		})
		return
	}
	if nftID == "" {
		c.Header("X-CBAC-Decision", "error")
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: fmt.Sprintf("agent %q has no nft_id on record", req.AgentID)})
		return
	}

	// Pass the resolved nft_id (not the DID) to the admin server as the agent_id.
	authorized, message, err := h.callAuthorizeAction(nftID, req.ActionIntent, req.AgentEnvelope)
	if err != nil {
		// Fail closed: if we can't get a decision, do not touch the App.
		c.Header("X-CBAC-Decision", "error")
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
		return
	}

	if !authorized {
		c.Header("X-CBAC-Decision", "deny")
		c.JSON(http.StatusForbidden, Response{
			Status: false,
			Data:   gin.H{"authorized": false, "message": message},
		})
		return
	}

	// Authorized. If the caller only wanted a decision, return it.
	if req.AppRequest == nil {
		c.Header("X-CBAC-Decision", "allow")
		c.JSON(http.StatusOK, Response{
			Status: true,
			Data:   gin.H{"authorized": true, "message": message},
		})
		return
	}

	// Authorized and an App call was supplied: forward it and relay the App's
	// response to the agent verbatim — same status, headers, and body. The
	// middleware does not reshape what the App returned (no X-CBAC-Decision
	// header here: its absence is how the caller knows this is the App's reply).
	statusCode, header, body, err := forwardToApp(req.AppRequest)
	if err != nil {
		c.Header("X-CBAC-Decision", "error")
		c.JSON(http.StatusBadGateway, Response{Status: false, Message: fmt.Sprintf("app forward error: %v", err)})
		return
	}

	relayHeaders(c, header)
	c.Status(statusCode)
	_, _ = c.Writer.Write(body)
}

// relayHeaders copies the App's response headers onto the outgoing response,
// skipping hop-by-hop / length headers that the Go server manages itself.
func relayHeaders(c *gin.Context, header http.Header) {
	dst := c.Writer.Header()
	for k, vals := range header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding", "Connection":
			continue
		}
		dst[k] = vals
	}
}

// callAuthorizeAction POSTs {agent_id, action_intent} to the admin server's
// authorize-action endpoint and returns its (authorized, message) decision.
func (h *Handler) callAuthorizeAction(agentID, actionIntent string, agentEnvelope *gin.H) (bool, string, error) {
	endpoint := h.adminServiceURL + "agent-admin/v1/authorize-action"

	b, err := json.Marshal(map[string]any{
		"agent_id": agentID,
		"action_intent": actionIntent,
		"agent_envelope": agentEnvelope,
	})
	if err != nil {
		return false, "", fmt.Errorf("callAuthorizeAction: marshal request: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(b))
	if err != nil {
		return false, "", fmt.Errorf("callAuthorizeAction: http post: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Authorized bool   `json:"authorized"`
		Message    string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", fmt.Errorf("callAuthorizeAction: decode response: %v", err)
	}

	return result.Authorized, result.Message, nil
}

// forwardToApp performs the agent's intended call against the downstream App
// and returns the App's status code, headers, and raw body for verbatim relay.
func forwardToApp(app *appRequest) (int, http.Header, []byte, error) {
	method := app.Method
	if method == "" {
		method = http.MethodPost
	}

	var bodyReader io.Reader
	if app.Body != "" {
		bodyReader = strings.NewReader(app.Body)
	}

	httpReq, err := http.NewRequest(method, app.URL, bodyReader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("forwardToApp: build request: %v", err)
	}
	for k, v := range app.Headers {
		httpReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("forwardToApp: do request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("forwardToApp: read response: %v", err)
	}

	return resp.StatusCode, resp.Header, body, nil
}
