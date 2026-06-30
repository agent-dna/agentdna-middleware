package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"
	"agentdna-ratelimit-auth/email"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
}

type Handler struct {
	db                  *db.DB
	proxy               *httputil.ReverseProxy
	baseURL             *url.URL
	jwtSecret           string
	orgID               string
	adminServiceURL     string
	createAgentEndpoint string
	updateAgentEndpoint string
	mailer              *email.Mailer
}

func New(database *db.DB, backendURL *url.URL, jwtSecret, orgID, adminServiceURL, createAgentEndpoint, updateAgentEndpoint string) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	h := &Handler{
		db:                  database,
		proxy:               proxy,
		baseURL:             backendURL,
		jwtSecret:           jwtSecret,
		orgID:               orgID,
		adminServiceURL:     adminServiceURL,
		createAgentEndpoint: createAgentEndpoint,
		updateAgentEndpoint: updateAgentEndpoint,
	}
	if cfg, err := email.LoadConfigFromEnv(); err == nil {
		h.mailer = email.New(cfg)
	} else {
		log.Printf("[email] mailer disabled: %v", err)
	}
	return h
}

// sendMail fires an email in a goroutine so it never blocks the request path.
// It is a no-op when no mailer is configured.
func (h *Handler) sendMail(msg email.Message, err error) {
	if err != nil || h.mailer == nil {
		return
	}
	go func() {
		if sendErr := h.mailer.Send(msg); sendErr != nil {
			log.Printf("[email] send to %s failed: %v", msg.To, sendErr)
		}
	}()
}

func (h *Handler) Healthz(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)
	c.JSON(200, gin.H{"status": "ok"})
}


func (h *Handler) ProxyHandler(c *gin.Context) {
	r := c.Request
	w := c.Writer

	if r.Method == http.MethodPost {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
       fmt.Print("ProxyHandler: received POST body: ", string(bodyBytes), "\n")

		var payload txPayload
		if jsonErr := json.Unmarshal(bodyBytes, &payload); jsonErr == nil && len(payload.Tokens.NFT) > 0 {
			fmt.Printf("ProxyHandler: TEST_01", payload.Tokens.NFT[0])
			nftInfo := payload.Tokens.NFT[0]
			nftType, typeErr := parseNFTType(nftInfo.Data)
			log.Printf("[NFT] received nft_id=%s type=%s data=%s", nftInfo.NFTId, nftType, nftInfo.Data)
			if typeErr == nil {
				switch nftType {
				// case NFTTypeUser:
				// 	h.handleUserNFT(nftInfo)
				case NFTTypeAgent:
					h.handleAgentNFT(nftInfo)
				case NFTTypeIntent:
					h.handleIntentWorkflow(nftInfo)
				}
			}
		}
	}
	
	h.proxy.ServeHTTP(w, r)
}


func (h *Handler) handleUserNFT(nftInfo NFTInfo) error {
	data, err := parseUserNFT(nftInfo.Data)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test123"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("handleUserNFT: hash default password: %v", err)
	}
	return h.db.StoreOrgUser(nftInfo.NFTId, data.UserDID, data.Metadata.OrgID, data.Metadata.Name, data.Metadata.Email, string(hash))
}

func (h *Handler) handleAgentNFT(nftInfo NFTInfo) error {
	fmt.Printf("[agentNFT] received nft_id=%s data=%s\n", nftInfo.NFTId, nftInfo.Data)
	data, err := parseAgentNFT(nftInfo.Data)
	if err != nil {
		return err
	}
	deployer := data.AgentMetadata.Deployer
	if deployer == "" {
		deployer = "User_One"
	}
	orgID := data.AgentMetadata.OrgID
	if orgID == "" {
		orgID = "Test_Org"
	}
	agentName := data.AgentMetadata.AgentName
	if agentName == "" {
		const defaultPrefix = "Agent_Finance"
		count, _ := h.db.CountAgentsWithNamePrefix(defaultPrefix)
		agentName = fmt.Sprintf("%s_%d", defaultPrefix, count+1)
	}

	return h.db.StoreNewAgent(nftInfo.NFTId, data.AgentDID, deployer, orgID, data.Policy, agentName)
}

func (h *Handler) handleIntentWorkflow(nftInfo NFTInfo) error {
	data, err := parseIntentWorkflow(nftInfo.Data)
	if err != nil {
		log.Printf("[intentWorkflow] failed to parse nft_id=%s: %v", nftInfo.NFTId, err)
		return err
	}
	if data.Envelope == nil {
		log.Printf("[intentWorkflow] envelope is nil nft_id=%s", nftInfo.NFTId)
		return fmt.Errorf("handleIntentWorkflow: envelope is nil")
	}

	envelopes := walkEnvelopes(data.Envelope)
	fmt.Printf("test envelopers: %v\n", envelopes)
	intentID := uuid.New().String()
	interactions := extractInteractionsFromEnvelopes(envelopes)

	log.Printf("[intentWorkflow] parsed ok — envelopes=%d interactions=%d", len(envelopes), len(interactions))
	for i, ix := range interactions {
		log.Printf("[intentWorkflow] interaction[%d] from=%s(%s) to=%s(%s) type=%s threat=%v",
			i, ix.FromName, ix.FromDID, ix.ToName, ix.ToDID, ix.Type, ix.Threat)
	}

	// ── Resolve org ──────────────────────────────────────────────────────────
	orgID := ""
	for _, ix := range interactions {
		if orgID == "" {
			orgID, _ = h.db.GetAgentOrgID(ix.FromDID)
		}
		if orgID == "" {
			orgID, _ = h.db.GetAgentOrgID(ix.ToDID)
		}
		if orgID != "" {
			break
		}
	}
	if orgID == "" {
		orgID = "Test_Org"
	}
	log.Printf("[intentWorkflow] orgID=%s intentID=%s", orgID, intentID)

	// ── Initiator is the from-actor of the oldest envelope ───────────────────
	initiatorDID := ""
	initiatorName := ""
	if len(envelopes) > 0 {
		initiatorDID = envelopes[0].From.ID
		initiatorName = envelopes[0].From.Name
	}

	// ── Ensure agents exist ──────────────────────────────────────────────────
	seen := map[string]bool{}
	for _, e := range envelopes {
		for _, actor := range []workflowActor{e.From, e.To} {
			if actor.Type != "agent" || actor.ID == "" || seen[actor.ID] {
				continue
			}
			seen[actor.ID] = true
			if err := h.db.StoreNewAgent(uuid.New().String(), actor.ID, initiatorDID, orgID, "", actor.Name); err != nil {
				log.Printf("[intentWorkflow] StoreNewAgent did=%s name=%s: %v", actor.ID, actor.Name, err)
			} else {
				log.Printf("[intentWorkflow] agent saved did=%s name=%s", actor.ID, actor.Name)
			}
		}
	}

	// ── Ensure initiator user exists if human ────────────────────────────────
	if len(envelopes) > 0 && envelopes[0].From.Type == "human" && initiatorDID != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte("test123"), bcrypt.DefaultCost)
		userNFTID, _ := GetID(initiatorDID)
		_ = h.db.StoreOrgUser(userNFTID, initiatorDID, orgID, initiatorName, initiatorName, string(hash))
		log.Printf("[intentWorkflow] user saved did=%s name=%s", initiatorDID, initiatorName)
	}

	// ── Store interactions ───────────────────────────────────────────────────
	threatDetected := false
	interactionIDs := make([]string, 0, len(interactions))
	for idx, ix := range interactions {
		iid := fmt.Sprintf("%s-%d", intentID, idx+1)
		interactionIDs = append(interactionIDs, iid)
		if ix.Threat {
			threatDetected = true
		}
		if err := h.db.StoreNewInteraction(
			iid, ix.FromDID, ix.FromName, ix.ToDID, ix.ToName, ix.Type, "", ix.Threat, intentID, orgID,
		); err != nil {
			return fmt.Errorf("handleIntentWorkflow: StoreNewInteraction: %v", err)
		}
		if ix.Type == "tool_call" {
			_ = h.db.StoreNewTool(ix.ToDID, ix.ToName, orgID)
		}
	}

	// ── Store intent ─────────────────────────────────────────────────────────
	flowType := detectFlowTypeFromExtracts(interactions)
	chainDepth := len(envelopes)
	executor := initiatorName
	if executor == "" {
		executor = initiatorDID
	}

	if err := h.db.StoreIntent(intentID, initiatorDID, orgID, flowType, executor, chainDepth, threatDetected, interactionIDs); err != nil {
		log.Printf("[intentWorkflow] intent save error: %v", err)
		return err
	}
	log.Printf("[intentWorkflow] saved intent_id=%s interactions=%d threat=%v flowType=%s", intentID, len(interactionIDs), threatDetected, flowType)
	return nil
}

func (h *Handler) handleIntentNFT(nftInfo NFTInfo) error {
	log.Printf("[intentNFT] received nft_id=%s", nftInfo)

	data, err := parseChainNFT(nftInfo.Data)
	if err != nil {
		log.Printf("[intentNFT] failed to parse chain nft_id=%s: %v", nftInfo.NFTId, err)
		return err
	}
	if data.Chain == nil {
		log.Printf("[intentNFT] chain is nil nft_id=%s", nftInfo.NFTId)
		return fmt.Errorf("handleIntentNFT: chain is nil")
	}

	log.Printf("[intentNFT] parsed ok — type=%s executor=%s chain_depth=%d trust_status=%s trust_issues=%v",
		data.Type, data.Executor, data.Verification.ChainDepth, data.Verification.Status, data.Verification.TrustIssues)

	blocks := walkChain(data.Chain)
	intentID := nftInfo.NFTId
	interactions := extractInteractions(blocks)

	log.Printf("[intentNFT] extracted blocks=%d interactions=%d", len(blocks), len(interactions))
	// ── Log extracted content ────────────────────────────────────────────────


	for i, ix := range interactions {
		log.Printf("[intentNFT] interaction[%d] from=%s(%s) to=%s(%s) type=%s threat=%v",
			i, ix.FromName, ix.FromDID, ix.ToName, ix.ToDID, ix.Type, ix.Threat)
	}

	for _, b := range blocks {
		if b.Type == "delegate" || b.Type == "execute" {
			log.Printf("[intentNFT] agent did=%s name=%s", b.Agent, b.Name)
		}
	}

	// ── 3. Resolve org ───────────────────────────────────────────────────────
	orgID := ""
	for _, b := range blocks {
		if b.Type == "delegate" || b.Type == "execute" {
			orgID, _ = h.db.GetAgentOrgID(b.Agent)
			if orgID != "" {
				break
			}
		}
	}
	if orgID == "" {
		orgID = "Test_Org"
	}

	initiatorDID := ""
	if len(blocks) > 0 {
		initiatorDID = blocks[0].Agent
	}
    
	log.Printf("[intentNFT] blocks=%d org=%s initiator=%s", len(blocks), orgID, initiatorDID)
	// ── 4. Ensure agents exist (create with defaults if missing) ─────────────
	for _, b := range blocks {
		log.Printf("[intentNFT] block did=%s type=%s name=%s", b.Agent, b.Type, b.Name)
		

		agentName := b.Name
		log.Printf("[intentNFT] processing agent did=%s name=%s org=%s", b.Agent, agentName, orgID)
		if agentName == "" {
			const defaultPrefix = "Agent_Finance"
			count, _ := h.db.CountAgentsWithNamePrefix(defaultPrefix)
			agentName = fmt.Sprintf("%s_%d", defaultPrefix, count+1)
		}
		if err := h.db.StoreNewAgent(uuid.New().String(), b.Agent, "User_One", orgID, "", agentName); err != nil {
			log.Fatalf("[intentNFT] agent save error did=%s: %v", b.Agent, err)
		} else {
			log.Printf("[intentNFT] agent saved did=%s name=%s org=%s", b.Agent, agentName, orgID)
		}
	}

	// ── 5. Ensure initiator user exists ──────────────────────────────────────
	if initiatorDID != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte("test123"), bcrypt.DefaultCost)
		userNFTID, _ := GetID(initiatorDID)
		_ = h.db.StoreOrgUser(userNFTID, initiatorDID, orgID, "", "", string(hash))
	}

	// ── 6. Store interactions ────────────────────────────────────────────────
	flowType := detectFlowType(blocks)
	executor := data.Executor
	if executor == "" {
		executor = "user"
	}
	chainDepth := data.Verification.ChainDepth
	threatDetected := data.Verification.Status != "ok" || len(data.Verification.TrustIssues) > 0

	interactionIDs := make([]string, 0, len(interactions))
	for idx, ix := range interactions {
		iid := fmt.Sprintf("%s-%d", intentID, idx+1)
		interactionIDs = append(interactionIDs, iid)
		if err := h.db.StoreNewInteraction(
			iid, ix.FromDID, ix.FromName, ix.ToDID, ix.ToName, ix.Type, ix.Direction, ix.Threat, intentID, orgID,
		); err != nil {
			return fmt.Errorf("handleIntentNFT: StoreNewInteraction: %v", err)
		}
		if ix.Type == "tool_call" {
			_ = h.db.StoreNewTool(ix.ToDID, ix.ToName, orgID)
		}
	}

	// ── 6b. Store per-block payload data ────────────────────────────────────
	for idx, b := range blocks {
		getString := func(m map[string]any, key string) string {
			if v, ok := m[key]; ok {
				switch s := v.(type) {
				case string:
					return s
				default:
					bs, _ := json.Marshal(v)
					return string(bs)
				}
			}
			return ""
		}

		msg := getString(b.Envelope.Payload, "original_message")
		if msg == "" {
			msg = getString(b.Envelope.Payload, "message")
		}

		cbacApp, cbacDecision := "", ""
		if cbacRaw, ok := b.Envelope.Payload["cbac"]; ok && cbacRaw != nil {
			if cbacMap, ok := cbacRaw.(map[string]any); ok {
				cbacApp, _ = cbacMap["app"].(string)
				cbacDecision, _ = cbacMap["decision"].(string)
			}
		}

		threat := cbacDecision == "deny" || !b.Verification.SignatureValid || len(b.Verification.TrustIssues) > 0

		rec := &db.IntentBlockRecord{
			ID:             fmt.Sprintf("%s-block-%d", intentID, idx),
			IntentID:       intentID,
			BlockIndex:     idx,
			AgentDID:       b.Agent,
			AgentName:      b.Name,
			Direction:      b.Direction,
			BlockType:      b.Type,
			Message:        msg,
			Response:       getString(b.Envelope.Payload, "response"),
			DelegateTo:     getString(b.Envelope.Payload, "delegate_to"),
			ReceivedFrom:   getString(b.Envelope.Payload, "received_from"),
			CbacApp:        cbacApp,
			CbacDecision:   cbacDecision,
			ThreatDetected: threat,
			TrustIssues:    b.Verification.TrustIssues,
		}
		if err := h.db.StoreIntentBlockData(rec); err != nil {
			log.Printf("[intentNFT] block data save error idx=%d: %v", idx, err)
		}
	}

	// ── 7. Store intent ──────────────────────────────────────────────────────
	if err := h.db.StoreIntent(intentID, initiatorDID, orgID, flowType, executor, chainDepth, threatDetected, interactionIDs); err != nil {
		log.Printf("[intentNFT] intent save error: %v", err)
		return err
	}
	log.Printf("[intentNFT] saved intent_id=%s interactions=%d", intentID, len(interactionIDs))
	return nil
}

func (h *Handler) GetIntentBlockData(c *gin.Context) {
	intentID := c.Query("intent_id")
	if intentID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "intent_id is required"})
		return
	}
	blocks, err := h.db.GetIntentBlocksByIntent(intentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: err.Error()})
		return
	}
	type blockOut struct {
		ID             string   `json:"id"`
		BlockIndex     int      `json:"block_index"`
		AgentDID       string   `json:"agent_did"`
		AgentName      string   `json:"agent_name"`
		Direction      string   `json:"direction"`
		BlockType      string   `json:"block_type"`
		Message        string   `json:"message"`
		Response       string   `json:"response"`
		DelegateTo     string   `json:"delegate_to"`
		ReceivedFrom   string   `json:"received_from"`
		CbacApp        string   `json:"cbac_app"`
		CbacDecision   string   `json:"cbac_decision"`
		ThreatDetected bool     `json:"threat_detected"`
		TrustIssues    []string `json:"trust_issues"`
	}
	out := make([]blockOut, 0, len(blocks))
	for _, b := range blocks {
		issues := b.TrustIssues
		if issues == nil {
			issues = []string{}
		}
		out = append(out, blockOut{
			ID:             b.ID,
			BlockIndex:     b.BlockIndex,
			AgentDID:       b.AgentDID,
			AgentName:      b.AgentName,
			Direction:      b.Direction,
			BlockType:      b.BlockType,
			Message:        b.Message,
			Response:       b.Response,
			DelegateTo:     b.DelegateTo,
			ReceivedFrom:   b.ReceivedFrom,
			CbacApp:        b.CbacApp,
			CbacDecision:   b.CbacDecision,
			ThreatDetected: b.ThreatDetected,
			TrustIssues:    issues,
		})
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: out})
}

func (h *Handler) issueToken(claims JWTClaims) (string, error) {
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(h.jwtSecret))
}

func (h *Handler) Login(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email and password are required"})
		return
	}


	// Try org user first
	user, err := h.db.GetOrgUserByEmail(req.Email)
	log.Printf("[Login] GetOrgUserByEmail email=%q found=%v err=%v", req.Email, err == nil, err)
	if err == nil {
		log.Printf("[Login] user did=%q orgID=%q hasPasswordHash=%v", user.DID, user.OrganizationID, user.PasswordHash != "")
		if user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			log.Printf("[Login] password mismatch for user email=%q", req.Email)
			c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid credentials"})
			return
		}
		log.Printf("[Login] user login success email=%q did=%q", req.Email, user.DID)
		tokenStr, err := h.issueToken(JWTClaims{
			DID: user.DID, Email: user.Email, OrgID: user.OrganizationID,
			NFTID: user.NFTID, APIKey: user.APIKey,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, Response{
			Status: true,
			Data: gin.H{
				"token":             tokenStr,
				"did":               user.DID,
				"email":             user.Email,
				"org_id":            user.OrganizationID,
				"api_key":           user.APIKey,
				"nft_id":            user.NFTID,
				"is_admin":          false,
				"agent_access_list": user.AgentAccessList,
			},
		})
		return
	}

	// Try admin
	admin, err := h.db.GetAdminByEmail(req.Email)
	log.Printf("[Login] GetAdminByEmail email=%q found=%v err=%v", req.Email, err == nil, err)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid credentials"})
		return
	}
	log.Printf("[Login] admin did=%q orgID=%q hasPasswordHash=%v", admin.DID, admin.OrganizationID, admin.PasswordHash != "")
	if admin.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)) != nil {
		log.Printf("[Login] password mismatch for admin email=%q", req.Email)
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "invalid credentials"})
		return
	}
	log.Printf("[Login] admin login success email=%q did=%q", req.Email, admin.DID)
	tokenStr, err := h.issueToken(JWTClaims{
		DID: admin.DID, Email: admin.Email, OrgID: admin.OrganizationID,
		APIKey: admin.APIKey,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"token":    tokenStr,
			"did":      admin.DID,
			"email":    admin.Email,
			"org_id":   admin.OrganizationID,
			"api_key":  admin.APIKey,
			"is_admin": true,
		},
	})
}

func (h *Handler) Signup(c *gin.Context) {
	var req struct {
		DID      string `json:"did"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		OrgID    string `json:"orgID"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.DID == "" || req.Email == "" || req.Password == "" || req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "did, email, password and orgID are required"})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	nftID, err := GetID(req.DID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate nft id"})
		return
	}

	if err := h.db.StoreOrgUser(nftID, req.DID, req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to register user: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"did":   req.DID,
		"name":  req.Name,
		"email": req.Email,
		"orgID": req.OrgID,
	}})
}

func (h *Handler) RegisterAdminMiddleware(c *gin.Context) {
	var req struct {
		DID   string `json:"did"`
		OrgID string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.DID == "" || req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "did and org_id are required"})
		return
	}

	if err := h.db.StoreAdmin(req.DID, req.OrgID, "", "", ""); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to register admin: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"did": req.DID, "org_id": req.OrgID}})
}


func (h *Handler) CreateUser(c *gin.Context) {
	fmt.Printf("test create user")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		DID      string `json:"did"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		OrgID    string `json:"orgID"`
	}

	if err := c.ShouldBindJSON(&req); err != nil || req.DID == "" || req.Email == "" || req.Password == "" || req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "did, email, password and orgID are required"})
		return
	}
    fmt.Printf("test102: %+v\n", req)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	nftID, err := GetID(req.DID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate user nft id"})
		return
	}
	if err := h.db.StoreOrgUser(nftID, req.DID, req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create user: %v", err)})
		return
	}
		println("test104: user stored in DB with DID=", req.DID)


	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"did":   req.DID,
		"name":  req.Name,
		"email": req.Email,
		"orgID": req.OrgID,
	}})
}

func (h *Handler) CreateAdmin(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		OrgID    string `json:"orgID"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "username, email and password are required"})
		return
	}

	// Call external agent service to register admin and get DID.
	did, err := h.callRegisterAdmin(req.Username, req.OrgID, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	apiKey := uuid.New().String()
	if err := h.db.StoreAdmin(did, req.OrgID, apiKey, req.Email, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to store admin: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"did":    did,
		"email":  req.Email,
		"orgID":  req.OrgID,
		"apiKey": apiKey,
	}})
}

func (h *Handler) UserProfile(c *gin.Context) {
	email := c.GetString(CtxEmail)
	if email == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}
	profile, err := h.db.GetUserProfile(email)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "user not found"})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: profile})
}

func (h *Handler) AdminProfile(c *gin.Context) {
	email := c.GetString(CtxEmail)
	if email == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}
	profile, err := h.db.GetAdminProfile(email)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "admin not found"})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: profile})
}

func (h *Handler) GlobalStats(c *gin.Context) {
	stats, err := h.db.GetGlobalStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: stats})
}

func (h *Handler) HomeMetrics(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * 5

	metrics, err := h.db.GetOrgMetrics(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch metrics: %v", err)})
		return
	}

	agents, err := h.db.GetTopAgentsByOrg(orgID, 5, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch agents: %v", err)})
		return
	}

	agentList := make([]gin.H, 0, len(agents))
	for _, a := range agents {
		agentList = append(agentList, gin.H{
			"agentName":         a.AgentName,
			"agentID":           a.AgentDID,
			"totalInteractions": a.TotalInteractions,
			"totalThreats":      a.TotalThreats,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agentCount":        metrics.AgentCount,
			"intentCount":       metrics.IntentCount,
			"interactionsCount": metrics.InteractionsCount,
			"threatCount":       metrics.ThreatCount,
			"agentList":         agentList,
			"page":              page,
		},
	})
}

func (h *Handler) InteractionsList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	intentID := c.Query("intentID")

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	var total int
	var interactions []*db.InteractionRecord
	var err error

	if intentID != "" {
		total, err = h.db.CountInteractionsByOrgAndIntent(orgID, intentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
			return
		}
		interactions, err = h.db.GetInteractionsByOrgAndIntent(orgID, intentID, pageSize, offset)
	} else {
		total, err = h.db.CountInteractionsByOrg(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
			return
		}
		interactions, err = h.db.GetInteractionsByOrg(orgID, pageSize, offset)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		list = append(list, gin.H{
			"interactionID": i.InteractionID,
			"from":          i.From,
			"fromName":      i.FromName,
			"to":            i.To,
			"toName":        i.ToName,
			"type":          i.Type,
			"direction":     i.Direction,
			"threat":        i.Threat,
			"intentID":      i.IntentID,
			"time":          i.Time,
		})
	}

	totalPages := (total + pageSize - 1) / pageSize

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"interactionList": list,
			"total":           total,
			"page":            page,
			"pageSize":        pageSize,
			"totalPages":      totalPages,
		},
	})
}

func (h *Handler) ThreatsList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountThreatsByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count threats: %v", err)})
		return
	}

	threats, err := h.db.GetThreatsByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch threats: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(threats))
	for _, t := range threats {
		list = append(list, gin.H{
			"interactionID": t.InteractionID,
			"from":          t.From,
			"fromName":      t.FromName,
			"to":            t.To,
			"toName":        t.ToName,
			"type":          t.Type,
			"direction":     t.Direction,
			"intentID":      t.IntentID,
			"time":          t.Time,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"threatsList": list,
			"total":       total,
			"page":        page,
			"pageSize":    pageSize,
			"totalPages":  (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) TopThreatAgents(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 5
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountTopThreatAgentsByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count threat agents: %v", err)})
		return
	}

	agents, err := h.db.GetTopThreatAgentsByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch threat agents: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(agents))
	for _, a := range agents {
		list = append(list, gin.H{
			"agentDID":          a.AgentDID,
			"agentName":         a.AgentName,
			"totalInteractions": a.TotalInteractions,
			"totalThreats":      a.TotalThreats,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agentsList": list,
			"total":      total,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) IntentList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountIntentsByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
		return
	}

	intents, err := h.db.GetIntentsByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch intents: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"intentsList": buildIntentList(intents),
			"total":       total,
			"page":        page,
			"pageSize":    pageSize,
			"totalPages":  (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentMetrics(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 5

	bestPage := 1
	if p, err := strconv.Atoi(c.Query("bestPage")); err == nil && p > 0 {
		bestPage = p
	}
	worstPage := 1
	if p, err := strconv.Atoi(c.Query("worstPage")); err == nil && p > 0 {
		worstPage = p
	}

	metrics, err := h.db.GetOrgMetrics(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch metrics: %v", err)})
		return
	}

	bestAgents, err := h.db.GetTopAgentsByOrg(orgID, pageSize, (bestPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch best agents: %v", err)})
		return
	}

	worstAgents, err := h.db.GetBottomAgentsByOrg(orgID, pageSize, (worstPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch worst agents: %v", err)})
		return
	}

	toAgentList := func(agents []*db.AgentVolumeRecord) []gin.H {
		list := make([]gin.H, 0, len(agents))
		for _, a := range agents {
			list = append(list, gin.H{
				"agentName":         a.AgentName,
				"agentID":           a.AgentDID,
				"totalInteractions": a.TotalInteractions,
				"totalThreats":      a.TotalThreats,
			})
		}
		return list
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agentCount":            metrics.AgentCount,
			"interactionCount":      metrics.InteractionsCount,
			"threatCount":           metrics.ThreatCount,
			"bestPerformingAgents":  toAgentList(bestAgents),
			"worstPerformingAgents": toAgentList(worstAgents),
			"bestPage":              bestPage,
			"worstPage":             worstPage,
			"pageSize":              pageSize,
		},
	})
}

func (h *Handler) AgentsList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountAgentsByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count agents: %v", err)})
		return
	}

	agents, err := h.db.GetAgentsByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch agents: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(agents))
	for _, a := range agents {
		list = append(list, gin.H{
			"agentID":           a.AgentDID,
			"agentName":         a.AgentName,
			"createdAt":         a.CreatedAt,
			"deployer":          a.DeployerDID,
			"policy":            a.Policy,
			"totalInteractions": a.TotalInteractions,
			"totalThreats":      a.TotalThreats,
			"score":             a.Score,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agentsList": list,
			"total":      total,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) UsersList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountUsersByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count users: %v", err)})
		return
	}

	users, err := h.db.GetUsersByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch users: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(users))
	for _, u := range users {
		list = append(list, gin.H{
			"userID":           u.UserDID,
			"userName":         u.UserName,
			"createdAt":        u.CreatedAt,
			"totalIntents":     u.TotalIntents,
			"totalThreats":     u.TotalThreats,
			"accessAgentCount": u.AccessAgentCount,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"usersList":  list,
			"total":      total,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentInteractions(c *gin.Context) {
	agentDID := c.Query("agentDID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	agentOrgID, err := h.db.GetAgentOrgID(agentDID)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountInteractionsByAgent(agentDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
		return
	}

	interactions, err := h.db.GetInteractionsByAgent(agentDID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		list = append(list, gin.H{
			"interactionID": i.InteractionID,
			"from":          i.From,
			"fromName":      i.FromName,
			"to":            i.To,
			"toName":        i.ToName,
			"type":          i.Type,
			"direction":     i.Direction,
			"threat":        i.Threat,
			"intentID":      i.IntentID,
			"time":          i.Time,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"interactionsList": list,
			"total":            total,
			"page":             page,
			"pageSize":         pageSize,
			"totalPages":       (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentIntents(c *gin.Context) {
	agentDID := c.Query("agentDID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	agentOrgID, err := h.db.GetAgentOrgID(agentDID)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountAgentIntents(agentDID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
		return
	}

	intents, err := h.db.GetAgentIntents(agentDID, orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch intents: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"intentsList": buildIntentList(intents),
			"total":       total,
			"page":        page,
			"pageSize":    pageSize,
			"totalPages":  (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) UserIntents(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	userDID := c.GetString(CtxDID)
	orgID := c.GetString(CtxOrgID)
	if userDID == "" || orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountUserIntents(userDID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
		return
	}

	intents, err := h.db.GetUserIntents(userDID, orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch intents: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"intentsList": buildIntentList(intents),
			"total":       total,
			"page":        page,
			"pageSize":    pageSize,
			"totalPages":  (total + pageSize - 1) / pageSize,
		},
	})
}

func buildIntentList(intents []*db.IntentRecord) []gin.H {
	list := make([]gin.H, 0, len(intents))
	for _, i := range intents {
		entry := gin.H{
			"intentID":          i.IntentID,
			"initiatorDID":      i.InitiatorDID,
			"initiatorName":     i.InitiatorName,
			"startedAt":         i.StartedAt,
			"status":            i.Status,
			"threatDetected":    i.ThreatDetected,
			"flowType":          i.FlowType,
			"executor":          i.Executor,
			"chainDepth":        i.ChainDepth,
			"interactionsCount":  i.InteractionsCount,
			"agentsCount":        i.AgentsCount,
			"toolsCount":         i.ToolsCount,
			"threatCount":        i.ThreatCount,
			"firstInteractionAt": i.FirstInteractionAt,
			"lastInteractionAt":  i.LastInteractionAt,
			"runtimeSeconds":     i.RuntimeSeconds,
		}
		if i.EndedAt != nil {
			entry["endedAt"] = i.EndedAt
		}
		list = append(list, entry)
	}
	return list
}

func (h *Handler) IntentDiagram(c *gin.Context) {
	intentID := c.Query("intentID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if intentID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "intentID is required"})
		return
	}

	intent, err := h.db.GetIntentInfo(intentID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "intent not found"})
		return
	}
	if intent.OrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	interactions, err := h.db.GetInteractionsByIntent(intentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}

	type DiagramNode struct {
		DID             string         `json:"did"`
		Name            string         `json:"name"`
		InteractionID   string         `json:"interactionID,omitempty"`
		InteractionType string         `json:"interactionType,omitempty"`
		Direction       string         `json:"direction,omitempty"`
		Threat          bool           `json:"threat"`
		Children        []*DiagramNode `json:"children"`
	}

	root := &DiagramNode{
		DID:      intent.InitiatorDID,
		Name:     intent.InitiatorName,
		Children: []*DiagramNode{},
	}

	// Stack tracks the current path from root to the active node.
	stack := []*DiagramNode{root}

	for _, ix := range interactions {
		current := stack[len(stack)-1]

		if ix.Direction == "outbound" {
			child := &DiagramNode{
				DID:             ix.To,
				Name:            ix.ToName,
				InteractionID:   ix.InteractionID,
				InteractionType: ix.Type,
				Direction:       ix.Direction,
				Threat:          ix.Threat,
				Children:        []*DiagramNode{},
			}
			current.Children = append(current.Children, child)
			stack = append(stack, child)
		} else {
			// inbound — pop back up, but keep at least root on the stack
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"intentID":  intentID,
			"diagram":   root,
		},
	})
}

func (h *Handler) AgentInfo(c *gin.Context) {
	agentDID := c.Query("agentDID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	agentOrgID, err := h.db.GetAgentOrgID(agentDID)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	agent, err := h.db.GetAgentInfo(agentDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch agent info: %v", err)})
		return
	}

	deployerName, _ := h.db.GetOrgUserNameByDID(agent.DeployerDID)

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agentDID":          agent.AgentDID,
			"agentName":         agent.AgentName,
			"createdAt":         agent.CreatedAt,
			"deployerDID":       agent.DeployerDID,
			"deployerName":      deployerName,
			"policy":            agent.Policy,
			"orgID":             orgID,
			"totalInteractions": agent.TotalInteractions,
			"totalThreats":      agent.TotalThreats,
			"score":             agent.Score,
		},
	})
}

func (h *Handler) IntentInfo(c *gin.Context) {
	intentID := c.Query("intentID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if intentID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "intentID is required"})
		return
	}

	intent, err := h.db.GetIntentInfo(intentID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "intent not found"})
		return
	}
	if intent.OrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	interactions, err := h.db.GetInteractionsByIntent(intentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}

	txns := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		txns = append(txns, gin.H{
			"interactionID": i.InteractionID,
			"from":          i.From,
			"fromName":      i.FromName,
			"to":            i.To,
			"toName":        i.ToName,
			"type":          i.Type,
			"direction":     i.Direction,
			"threat":        i.Threat,
			"time":          i.Time,
		})
	}

	data := gin.H{
		"intentID":          intent.IntentID,
		"initiatorDID":      intent.InitiatorDID,
		"initiatorName":     intent.InitiatorName,
		"startedAt":         intent.StartedAt,
		"status":            intent.Status,
		"threatDetected":    intent.ThreatDetected,
		"flowType":          intent.FlowType,
		"executor":          intent.Executor,
		"chainDepth":        intent.ChainDepth,
		"interactionsCount": intent.InteractionsCount,
		"agentsCount":       intent.AgentsCount,
		"toolsCount":        intent.ToolsCount,
		"firstInteractionAt": intent.FirstInteractionAt,
		"lastInteractionAt":  intent.LastInteractionAt,
		"runtimeSeconds":     intent.RuntimeSeconds,
		"interactions":      txns,
	}
	if intent.EndedAt != nil {
		data["endedAt"] = intent.EndedAt
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

func (h *Handler) ToolsList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountToolsByOrg(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count tools: %v", err)})
		return
	}

	tools, err := h.db.GetToolsByOrg(orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch tools: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(tools))
	for _, t := range tools {
		list = append(list, gin.H{
			"toolDID":           t.DID,
			"toolName":          t.Name,
			"totalInteractions": t.TotalInteractions,
			"totalThreats":      t.TotalThreats,
			"totalIntents":      t.TotalIntents,
			"score":             t.Score,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"toolsList":  list,
			"total":      total,
			"page":       page,
			"pageSize":   pageSize,
			"totalPages": (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) ToolInfo(c *gin.Context) {
	toolDID := c.Query("toolDID")
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if toolDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "toolDID is required"})
		return
	}

	tool, err := h.db.GetToolInfo(toolDID, orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "tool not found"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountInteractionsByTool(toolDID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
		return
	}

	interactions, err := h.db.GetInteractionsByTool(toolDID, orgID, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		list = append(list, gin.H{
			"interactionID": i.InteractionID,
			"from":          i.From,
			"fromName":      i.FromName,
			"type":          i.Type,
			"direction":     i.Direction,
			"threat":        i.Threat,
			"intentID":      i.IntentID,
			"time":          i.Time,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"toolDID":           tool.DID,
			"toolName":          tool.Name,
			"totalInteractions": tool.TotalInteractions,
			"totalThreats":      tool.TotalThreats,
			"totalIntents":      tool.TotalIntents,
			"score":             tool.Score,
			"interactions":      list,
			"total":             total,
			"page":              page,
			"pageSize":          pageSize,
			"totalPages":        (total + pageSize - 1) / pageSize,
		},
	})
}

// callRegisterAdmin calls the external agent service to register an admin and get their DID.
func (h *Handler) callRegisterAdmin(username, org, password string) (string, error) {
	endpoint := h.createAgentEndpoint + "agent-admin/v1/register-admin"

	b, _ := json.Marshal(map[string]string{"username": username, "org": org, "password": password})
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("callRegisterAdmin: http post: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if !result.Status {
		return "", fmt.Errorf("register admin failed: %s", result.Message)
	}
	return result.Message, nil // message = admin DID on success
}

// callCreateAgent POSTs multipart form-data to CREATE_AGENT_ENDPOINT.
// The agent DID is known upfront; the API returns the NFT ID for that agent.
func (h *Handler) callCreateAgent(agentName, policy, creatorDID, orgID string) (nftID string, err error) {
	if policy == "" {
		policy = "default policy"
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("creator_did", creatorDID)
	mw.WriteField("org_id", orgID)
	mw.WriteField("agent_name", agentName)
	fw, fwErr := mw.CreateFormFile("policy", "policy.txt")
	fmt.Printf("TEST--11: creatorDID=%q orgID=%q agentName=%q policy=%q\n", creatorDID, orgID, agentName, policy)
	if fwErr != nil {
		return "", fmt.Errorf("callCreateAgent: create form file: %v", fwErr)
	}
	if _, fwErr = fw.Write([]byte(policy)); fwErr != nil {
		return "", fmt.Errorf("callCreateAgent: write policy: %v", fwErr)
	}
	mw.Close()

	endpoint := h.createAgentEndpoint + "agent-admin/v1/create-agent"
	log.Printf("[callCreateAgent] POST %s", endpoint)
	httpStart := time.Now()
	resp, err := http.Post(endpoint, mw.FormDataContentType(), &buf)
	log.Printf("[callCreateAgent] http post took %s", time.Since(httpStart))
	if err != nil {
		return "", fmt.Errorf("callCreateAgent: http post: %v", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	log.Printf("[callCreateAgent] response status=%d body=%s", resp.StatusCode, string(rawBody))

	var result struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
		NFTID   string `json:"agent_id"`
	}
	json.Unmarshal(rawBody, &result)

	if !result.Status {
		return "", fmt.Errorf("create agent failed: %s", result.Message)
	}
	return result.NFTID, nil
}

// callUpdateAgent POSTs multipart form-data to UPDATE_AGENT_ENDPOINT.
func (h *Handler) callUpdateAgent(agentName, agentID, policy, creatorDID, orgID string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("creator_did", creatorDID)
	mw.WriteField("org_id", orgID)
	mw.WriteField("agent_name", agentName)
	mw.WriteField("agent_id", agentID)
	fw, err := mw.CreateFormFile("policy", "policy.txt")
	if err != nil {
		return fmt.Errorf("callUpdateAgent: create form file: %v", err)
	}
	if _, err = fw.Write([]byte(policy)); err != nil {
		return fmt.Errorf("callUpdateAgent: write policy: %v", err)
	}
	mw.Close()

	endpoint := h.updateAgentEndpoint + "agent-admin/v1/update-agent-policies"
	resp, err := http.Post(endpoint, mw.FormDataContentType(), &buf)
	if err != nil {
		return fmt.Errorf("callUpdateAgent: http post: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if !result.Status {
		return fmt.Errorf("update agent failed: %s", result.Message)
	}
	return nil
}

func (h *Handler) buildRequestList(requests []*db.RequestRecord) []gin.H {
	list := make([]gin.H, 0, len(requests))
	for _, r := range requests {
		list = append(list, gin.H{
			"requestID":   r.RequestID,
			"requestType": r.RequestType,
			"policy":      r.Policy,
			"creatorDID":  r.CreatorDID,
			"agentDID":    r.AgentDID,
			"agentName":   r.AgentName,
			"requestInfo": r.RequestInfo,
			"status":      r.Status,
			"createdAt":   r.CreatedAt,
		})
	}
	return list
}

func (h *Handler) SearchUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"message": "not implemented"})
}

// UploadUserPolicy accepts a multipart .md or .txt file and stores its
// content as the authenticated user's policy.
func (h *Handler) UploadUserPolicy(c *gin.Context) {
	userDID := c.GetString(CtxDID)
	if userDID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	content, ok := readPolicyFile(c)
	if !ok {
		return
	}

	if err := h.db.UpdateUserPolicy(userDID, content); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to save policy: %v", err)})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"message": "user policy updated"}})
}

// GetUserPolicy returns the authenticated user's stored policy content.
func (h *Handler) GetUserPolicy(c *gin.Context) {
	userDID := c.GetString(CtxDID)
	if userDID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	policy, err := h.db.GetUserPolicy(userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch policy: %v", err)})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"policy": policy}})
}

// UploadAgentPolicy accepts a multipart .md or .txt file and stores its
// content as the given agent's policy. Admin only.
func (h *Handler) UploadAgentPolicy(c *gin.Context) {
	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	agentDID := c.PostForm("agentDID")
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	content, ok := readPolicyFile(c)
	if !ok {
		return
	}

	agentInfo, err := h.db.GetAgentInfo(agentDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "agent not found"})
		return
	}
	orgID, _ := h.db.GetAgentOrgID(agentDID)
	if err := h.callUpdateAgent(agentInfo.AgentName, agentDID, content, agentInfo.DeployerDID, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
		return
	}

	if err := h.db.UpdateAgentPolicy(agentDID, content); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to save policy: %v", err)})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"message": "agent policy updated", "agentDID": agentDID}})
}

// GetAgentPolicy returns the stored policy content for a given agent.
func (h *Handler) GetAgentPolicy(c *gin.Context) {
	agentDID := c.Query("agentDID")
	orgID := c.GetString(CtxOrgID)
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	agentOrgID, err := h.db.GetAgentOrgID(agentDID)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized"})
		return
	}

	policy, err := h.db.GetAgentPolicy(agentDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch policy: %v", err)})
		return
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"agentDID": agentDID, "policy": policy}})
}

// fetchAgentChain is a shared helper that calls the Rubix node and returns
// all chain entries (skipping index 0 which is the initial deployment).
func (h *Handler) fetchAgentChain(nftID string) ([]struct {
	TransactionID string
	Epoch         int64
	Data          string
}, error) {
	chainURL := fmt.Sprintf("%s://%s/rubix/v1/nfts/%s/chain", h.baseURL.Scheme, h.baseURL.Host, nftID)
	resp, err := http.Get(chainURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var chainResp struct {
		Result []struct {
			TransactionID string `json:"transactionId"`
			Epoch         int64  `json:"epoch"`
			Data          string `json:"data"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chainResp); err != nil {
		return nil, err
	}

	if len(chainResp.Result) <= 1 {
		return nil, nil
	}

	var out []struct {
		TransactionID string
		Epoch         int64
		Data          string
	}
	for _, e := range chainResp.Result[1:] {
		out = append(out, struct {
			TransactionID string
			Epoch         int64
			Data          string
		}{e.TransactionID, e.Epoch, e.Data})
	}
	return out, nil
}

// GetAgentPolicyHistory returns only updateID + time for each policy update.
// Call GetAgentPolicyUpdate with a specific updateID to get the full policy text.
func (h *Handler) GetAgentPolicyHistory(c *gin.Context) {
	agentDID := c.Query("agentDID")
	if agentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}

	nftID, err := h.db.GetAgentNFTID(agentDID)
	if err != nil || nftID == "" {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "agent NFT not found"})
		return
	}

	entries, err := h.fetchAgentChain(nftID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch chain: %v", err)})
		return
	}

	type historyItem struct {
		UpdateID string `json:"updateID"`
		Time     int64  `json:"time"`
	}
	var history []historyItem
	for _, e := range entries {
		history = append(history, historyItem{UpdateID: e.TransactionID, Time: e.Epoch})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"agentDID": agentDID, "nftID": nftID, "history": history}})
}

// GetAgentPolicyUpdate returns the full decoded policy for a specific updateID.
func (h *Handler) GetAgentPolicyUpdate(c *gin.Context) {
	agentDID := c.Query("agentDID")
	updateID := c.Query("updateID")
	if agentDID == "" || updateID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID and updateID are required"})
		return
	}

	nftID, err := h.db.GetAgentNFTID(agentDID)
	if err != nil || nftID == "" {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "agent NFT not found"})
		return
	}

	entries, err := h.fetchAgentChain(nftID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch chain: %v", err)})
		return
	}

	for _, e := range entries {
		if e.TransactionID != updateID {
			continue
		}
		var data struct {
			Policy string `json:"policy"`
		}
		if err := json.Unmarshal([]byte(e.Data), &data); err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to parse entry data"})
			return
		}
		policyText := data.Policy
		if decoded, decErr := base64.StdEncoding.DecodeString(data.Policy); decErr == nil {
			policyText = string(decoded)
		}
		c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"updateID": updateID, "time": e.Epoch, "policy": policyText}})
		return
	}

	c.JSON(http.StatusNotFound, Response{Status: false, Message: "updateID not found in chain"})
}

// readPolicyFile reads a multipart "file" field from the request,
// validates it is .md or .txt, and returns the content as a string.
func readPolicyFile(c *gin.Context) (string, bool) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "file is required"})
		return "", false
	}

	name := fileHeader.Filename
	if len(name) < 4 {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "file must be .md or .txt"})
		return "", false
	}
	ext := name[len(name)-3:]
	if ext != ".md" && name[len(name)-4:] != ".txt" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "only .md and .txt files are accepted"})
		return "", false
	}

	const maxSize = 1 << 20 // 1 MB
	if fileHeader.Size > maxSize {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "file too large (max 1 MB)"})
		return "", false
	}

	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to open file"})
		return "", false
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to read file"})
		return "", false
	}
	return string(raw), true
}

func (h *Handler) AgentsCreationRequestsList(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountRequestsByOrg(orgID, "deploy_agent")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count requests: %v", err)})
		return
	}

	requests, err := h.db.GetRequestsByOrg(orgID, "deploy_agent", pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch requests: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"requestsList": h.buildRequestList(requests),
			"total":        total,
			"page":         page,
			"pageSize":     pageSize,
			"totalPages":   (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentsCreationRequestsListUser(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	creatorDID := c.GetString(CtxDID)
	email := c.GetString(CtxEmail)
	log.Printf("[AgentsCreationRequestsListUser] ctx did=%q email=%q org_id=%q", creatorDID, email, c.GetString(CtxOrgID))
	if creatorDID == "" && email != "" {
		if u, err := h.db.GetOrgUserByEmail(email); err == nil && u.DID != "" {
			creatorDID = u.DID
			log.Printf("[AgentsCreationRequestsListUser] resolved did=%q from email=%q", creatorDID, email)
		}
	}
	if creatorDID == "" {
		log.Printf("[AgentsCreationRequestsListUser] rejecting — could not resolve DID")
		c.JSON(http.StatusOK, Response{Status: false, Message: "no_did", Data: map[string]string{"email": email}})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountRequestsByUser(creatorDID, "deploy_agent")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count requests: %v", err)})
		return
	}

	requests, err := h.db.GetRequestsByUser(creatorDID, "deploy_agent", pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch requests: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"requestsList": h.buildRequestList(requests),
			"total":        total,
			"page":         page,
			"pageSize":     pageSize,
			"totalPages":   (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentsCreationRequestsCreate(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	creatorDID := c.GetString(CtxDID)
	orgID := c.GetString(CtxOrgID)
	if creatorDID == "" || orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	// Support both JSON and multipart/form-data.
	agentName := c.PostForm("agentName")
	agentID := c.PostForm("agentID")
	requestInfo := c.PostForm("requestInfo")
	policy := ""

	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var body struct {
			AgentName   string `json:"agentName"`
			AgentID     string `json:"agentID"`
			RequestInfo string `json:"requestInfo"`
			Policy      string `json:"policy"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			agentName = body.AgentName
			agentID = body.AgentID
			requestInfo = body.RequestInfo
			policy = body.Policy
		}
	} else {
		// Multipart: try file upload first, then plain form field.
		if fh, err := c.FormFile("policy"); err == nil {
			f, err := fh.Open()
			if err == nil {
				defer f.Close()
				raw, _ := io.ReadAll(f)
				policy = string(raw)
			}
		}
		if policy == "" {
			policy = c.PostForm("policy")
		}
	}

	if agentName == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentName is required"})
		return
	}

	id := uuid.New().String()
	if err := h.db.CreateRequest(id, "deploy_agent", policy, creatorDID, agentID, agentName, requestInfo, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create request: %v", err)})
		return
	}

	// Notify admin.
	log.Printf("[AgentsCreationRequestsCreate] looking up admin for orgID=%q", orgID)
	if _, adminEmail, err := h.db.GetAdminEmailByOrgID(orgID); err != nil {
		log.Printf("[AgentsCreationRequestsCreate] GetAdminEmailByOrgID failed orgID=%q err=%v", orgID, err)
	} else {
		log.Printf("[AgentsCreationRequestsCreate] found admin email=%q, sending notification", adminEmail)
		requesterName, _, _ := h.db.GetOrgUserEmailByDID(creatorDID)
		log.Printf("[AgentsCreationRequestsCreate] requesterName=%q agentName=%q requestID=%q", requesterName, agentName, id)
		h.sendMail(email.AgentCreationRequestNew(adminEmail, agentName, requesterName, id))
		log.Printf("[AgentsCreationRequestsCreate] mail dispatched to admin=%q", adminEmail)
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"requestID": id}})
}

func (h *Handler) AgentsCreationRequestsEdit(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	creatorDID := c.GetString(CtxDID)
	if creatorDID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	var req struct {
		RequestID   string `json:"requestID"`
		AgentName   string `json:"agentName"`
		Policy      string `json:"policy"`
		RequestInfo string `json:"requestInfo"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.RequestID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "requestID is required"})
		return
	}

	existing, err := h.db.GetRequestByID(req.RequestID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "request not found"})
		return
	}
	if existing.CreatorDID != creatorDID {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "not authorized to edit this request"})
		return
	}
	if existing.Status != "pending" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "can only edit pending requests"})
		return
	}

	if err := h.db.UpdateRequest(req.RequestID, req.AgentName, req.Policy, req.RequestInfo); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update request: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"requestID": req.RequestID}})
}

func (h *Handler) AgentCreationRequestSubmit(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		RequestID string `json:"requestID"`
		Status    string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.RequestID == "" || req.Status == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "requestID and status are required"})
		return
	}
	if req.Status != "approved" && req.Status != "rejected" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "status must be 'approved' or 'rejected'"})
		return
	}

	existing, err := h.db.GetRequestByID(req.RequestID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "request not found"})
		return
	}

	submitStart := time.Now()
	if req.Status == "approved" {
		policy := existing.Policy
		if policy == "" {
			policy = "default policy"
		}
		adminDID := c.GetString(CtxDID)
		log.Printf("[AgentCreationRequestSubmit] calling create-agent requestID=%s agentDID=%s agentName=%s adminDID=%s", req.RequestID, existing.AgentDID, existing.AgentName, adminDID)
		callStart := time.Now()
		nftID, err := h.callCreateAgent(existing.AgentName, policy, adminDID, existing.OrgID)
		log.Printf("[AgentCreationRequestSubmit] create-agent call took %s", time.Since(callStart))
		if err != nil {
			log.Printf("[AgentCreationRequestSubmit] create-agent error after %s: %v", time.Since(callStart), err)
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
			return
		}
		log.Printf("[AgentCreationRequestSubmit] create-agent returned nftID=%s", nftID)
		if nftID == "" {
			nftID = uuid.New().String()
		}
		dbStart := time.Now()
		if err := h.db.StoreNewAgent(nftID, existing.AgentDID, existing.CreatorDID, existing.OrgID, policy, existing.AgentName); err != nil {
			log.Printf("[AgentCreationRequestSubmit] StoreNewAgent error: %v", err)
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to store agent: %v", err)})
			return
		}
		log.Printf("[AgentCreationRequestSubmit] agent stored agentDID=%s nftID=%s (db took %s)", existing.AgentDID, nftID, time.Since(dbStart))
	}

	if err := h.db.UpdateRequestStatus(req.RequestID, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update status: %v", err)})
		return
	}

	// Notify the request creator.
	if userName, userEmail, err := h.db.GetOrgUserEmailByDID(existing.CreatorDID); err == nil {
		h.sendMail(email.AgentCreationRequestStatus(userEmail, userName, existing.AgentName, req.Status))
	}

	log.Printf("[AgentCreationRequestSubmit] total request took %s requestID=%s status=%s", time.Since(submitStart), req.RequestID, req.Status)
	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"requestID": req.RequestID, "status": req.Status}})
}

func (h *Handler) AgentInfoEdit(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		AgentDID  string `json:"agentDID"`
		AgentName string `json:"agentName"`
		Policy    string `json:"policy"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agentDID is required"})
		return
	}


	// Look up org and NFT ID for the agent to pass to the update endpoint.
	orgID, _ := h.db.GetAgentOrgID(req.AgentDID)
	nftID, _ := h.db.GetAgentNFTID(req.AgentDID)
	if err := h.callUpdateAgent(req.AgentName, nftID, req.Policy, req.AgentDID, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
		return
	}

	if err := h.db.UpdateAgentInfo(req.AgentDID, req.AgentName, req.Policy); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update agent info: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"agentDID": req.AgentDID}})
}

func (h *Handler) AgentAccessRequestsListOrg(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountRequestsByOrg(orgID, "agent_access")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count requests: %v", err)})
		return
	}

	requests, err := h.db.GetRequestsByOrg(orgID, "agent_access", pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch requests: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"requestsList": h.buildRequestList(requests),
			"total":        total,
			"page":         page,
			"pageSize":     pageSize,
			"totalPages":   (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentAccessRequestsListUser(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	userDID := c.GetString(CtxDID)
	if userDID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountRequestsByUser(userDID, "agent_access")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count requests: %v", err)})
		return
	}

	requests, err := h.db.GetRequestsByUser(userDID, "agent_access", pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch requests: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"requestsList": h.buildRequestList(requests),
			"total":        total,
			"page":         page,
			"pageSize":     pageSize,
			"totalPages":   (total + pageSize - 1) / pageSize,
		},
	})
}

func (h *Handler) AgentAccessRequestSubmit(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		RequestID string `json:"requestID"`
		Status    string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.RequestID == "" || req.Status == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "requestID and status are required"})
		return
	}
	if req.Status != "approved" && req.Status != "rejected" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "status must be 'approved' or 'rejected'"})
		return
	}

	existing, err := h.db.GetRequestByID(req.RequestID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "request not found"})
		return
	}

	if req.Status == "approved" {
		if existing.CreatorDID == "" || existing.AgentDID == "" {
			c.JSON(http.StatusBadRequest, Response{Status: false, Message: "request missing user or agent info"})
			return
		}
		if err := h.db.AddAgentToUserAccessList(existing.CreatorDID, existing.AgentDID); err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to grant agent access: %v", err)})
			return
		}
	}

	if err := h.db.UpdateRequestStatus(req.RequestID, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update status: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"requestID": req.RequestID, "status": req.Status}})
}

func (h *Handler) RegisterUser(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		OrgID    string `json:"orgID"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" || req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email, password and orgID are required"})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	// Generate a unique api_key.
	apiKey := uuid.New().String()

	if err := h.db.RegisterOrgUser( apiKey, req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to register user: %v", err)})
		return
	}

	h.sendMail(email.UserRegistration(req.Email, req.Name))

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"api_key": apiKey,
		"name":    req.Name,
		"email":   req.Email,
		"orgID":   req.OrgID,
	}})
}