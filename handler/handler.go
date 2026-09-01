package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

type otpEntry struct {
	code      string
	expiresAt time.Time
}

const emailWorkers = 5
const emailQueueSize = 100

// Rubix blockchain transaction endpoints whose responses we capture for provenance.
const (
	rubixTxPath        = "/rubix/v1/tx"
	rubixSignaturePath = "/rubix/v1/signature"
)

// provenanceCtxKey is a private request-context key type used to carry a value from
// the request handler (ProxyHandler) to the response hook (captureRubixResponse).
type provenanceCtxKey string

const (
	// ctxIntentIDKey carries the intentID generated while handling a /tx intent
	// workflow so the /tx response hook can attach provenance_req_id to those rows.
	ctxIntentIDKey provenanceCtxKey = "provenance_intent_id"
	// ctxSignatureIDKey carries the id from a /signature request body so the
	// /signature response hook knows which provenance rows to update.
	ctxSignatureIDKey provenanceCtxKey = "provenance_signature_id"
)

type Handler struct {
	db                  *db.DB
	proxy               *httputil.ReverseProxy
	baseURL             *url.URL
	jwtSecret           string
	orgID               string
	adminServiceURL     string
	cbacServiceURL      string
	createAgentEndpoint string
	updateAgentEndpoint string
	mailer              *email.Mailer
	otpStore            sync.Map
	emailQueue          chan email.Message
}

func New(database *db.DB, backendURL *url.URL, jwtSecret, orgID, adminServiceURL, cbacServiceURL, createAgentEndpoint, updateAgentEndpoint string) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	h := &Handler{
		db:                  database,
		proxy:               proxy,
		baseURL:             backendURL,
		jwtSecret:           jwtSecret,
		orgID:               orgID,
		adminServiceURL:     adminServiceURL,
		cbacServiceURL:      cbacServiceURL,
		createAgentEndpoint: createAgentEndpoint,
		updateAgentEndpoint: updateAgentEndpoint,
		emailQueue:          make(chan email.Message, emailQueueSize),
	}
	// Capture blockchain transaction provenance from the upstream responses.
	proxy.ModifyResponse = h.captureRubixResponse
	if cfg, err := email.LoadConfigFromEnv(); err == nil {
		h.mailer = email.New(cfg)
	} else {
		log.Printf("[email] mailer disabled: %v", err)
	}
	h.startEmailWorkers()
	return h
}

// startEmailWorkers spawns a fixed pool of goroutines that process the email queue.
// Workers run for the lifetime of the server — no unbounded goroutine spawning per request.
func (h *Handler) startEmailWorkers() {
	for i := range emailWorkers {
		go func(workerID int) {
			for msg := range h.emailQueue {
				if err := h.mailer.Send(msg); err != nil {
					log.Printf("[email] worker=%d send failed to=%q subject=%q err=%v", workerID, msg.To, msg.Subject, err)
				} else {
					log.Printf("[email] worker=%d sent ok to=%q subject=%q", workerID, msg.To, msg.Subject)
				}
			}
		}(i)
	}
	log.Printf("[email] started %d email workers (queue capacity=%d)", emailWorkers, emailQueueSize)
}

func generateOTP() (string, error) {
	var otp string
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp += n.String()
	}
	return otp, nil
}

func (h *Handler) SendOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email is required"})
		return
	}

	code, err := generateOTP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate OTP"})
		return
	}

	h.otpStore.Store(req.Email, otpEntry{
		code:      code,
		expiresAt: time.Now().Add(5 * time.Minute),
	})

	h.sendMail(email.OTPVerification(req.Email, code))
	log.Printf("[SendOTP] OTP sent to email=%q", req.Email)
	c.JSON(http.StatusOK, Response{Status: true, Message: "OTP sent to " + req.Email})
}

func (h *Handler) verifyOTP(emailAddr, code string) bool {
	val, ok := h.otpStore.Load(emailAddr)
	if !ok {
		return false
	}
	entry := val.(otpEntry)
	if time.Now().After(entry.expiresAt) {
		h.otpStore.Delete(emailAddr)
		return false
	}
	if entry.code != code {
		return false
	}
	h.otpStore.Delete(emailAddr)
	return true
}

func (h *Handler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email is required"})
		return
	}

	// Confirm the email belongs to a known user or admin before sending OTP.
	isUser := true
	if _, err := h.db.GetOrgUserByEmail(req.Email); err != nil {
		if _, err := h.db.GetAdminByEmail(req.Email); err != nil {
			c.JSON(http.StatusNotFound, Response{Status: false, Message: "no account found with that email"})
			return
		}
		isUser = false
	}
	_ = isUser

	code, err := generateOTP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to generate OTP"})
		return
	}
	h.otpStore.Store(req.Email, otpEntry{code: code, expiresAt: time.Now().Add(5 * time.Minute)})
	h.sendMail(email.OTPVerification(req.Email, code))
	log.Printf("[ForgotPassword] OTP sent to email=%q", req.Email)
	c.JSON(http.StatusOK, Response{Status: true, Message: "OTP sent to " + req.Email})
}

func (h *Handler) ResetPassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email"`
		OTP         string `json:"otp"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.OTP == "" || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email, otp and new_password are required"})
		return
	}
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "password must be at least 8 characters"})
		return
	}
	if !h.verifyOTP(req.Email, req.OTP) {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid or expired OTP"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	// Try user first, then admin.
	if err := h.db.UpdateUserPassword(req.Email, string(hash)); err != nil {
		if err := h.db.UpdateAdminPassword(req.Email, string(hash)); err != nil {
			c.JSON(http.StatusNotFound, Response{Status: false, Message: "no account found with that email"})
			return
		}
	}

	log.Printf("[ResetPassword] password updated for email=%q", req.Email)
	c.JSON(http.StatusOK, Response{Status: true, Message: "password updated successfully"})
}

func (h *Handler) UpdatePassword(c *gin.Context) {
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "new_password is required"})
		return
	}
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "password must be at least 8 characters"})
		return
	}

	email := c.GetString(CtxEmail)
	isAdmin := c.GetBool(CtxIsAdmin)

	if isAdmin {
		admin, err := h.db.GetAdminByEmail(email)
		if err != nil {
			c.JSON(http.StatusNotFound, Response{Status: false, Message: "account not found"})
			return
		}

		// Call admin server to update password there.
		endpoint := h.adminServiceURL + "agent-admin/v1/update-password"
		b, _ := json.Marshal(map[string]string{"username": admin.Name, "new_password": req.NewPassword})
		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b))
		if err != nil {
			log.Printf("[UpdatePassword] admin server http error email=%s err=%v", email, err)
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to reach admin server: %v", err)})
			return
		}
		defer resp.Body.Close()

		var adminResp struct {
			Status  bool   `json:"status"`
			Message string `json:"message"`
		}
		rawBody, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(rawBody, &adminResp); err != nil {
			log.Printf("[UpdatePassword] failed to parse admin server response email=%s body=%s", email, string(rawBody))
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "invalid response from admin server"})
			return
		}
		if !adminResp.Status {
			log.Printf("[UpdatePassword] admin server rejected update email=%s message=%s", email, adminResp.Message)
			c.JSON(http.StatusBadRequest, Response{Status: false, Message: adminResp.Message})
			return
		}

	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
			return
		}
		if err := h.db.UpdateUserPassword(email, string(hash)); err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to update password"})
			return
		}
	}

	log.Printf("[UpdatePassword] password updated email=%q isAdmin=%v", email, isAdmin)
	c.JSON(http.StatusOK, Response{Status: true, Message: "password updated successfully"})
}

// sendMail enqueues an email for the worker pool. Never blocks the request path.
func (h *Handler) sendMail(msg email.Message, err error) {
	if err != nil {
		log.Printf("[email] template render failed: %v", err)
		return
	}
	if strings.TrimSpace(msg.To) == "" {
		log.Printf("[email] skipping — empty To address subject=%q", msg.Subject)
		return
	}
	if h.mailer == nil {
		log.Printf("[email] mailer not configured — skipping email to=%q subject=%q", msg.To, msg.Subject)
		return
	}
	select {
	case h.emailQueue <- msg:
		log.Printf("[email] queued to=%q subject=%q (queue len=%d)", msg.To, msg.Subject, len(h.emailQueue))
	default:
		log.Printf("[email] queue full — dropping email to=%q subject=%q", msg.To, msg.Subject)
	}
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

		var payload txPayload
		if jsonErr := json.Unmarshal(bodyBytes, &payload); jsonErr == nil && len(payload.Tokens.NFT) > 0 {
			nftInfo := payload.Tokens.NFT[0]
			if nftInfo.NFTId == "" {
				nftInfo.NFTId = nftInfo.ParentNFTId
			}
			nftInfo.Initiator = payload.Initiator
			log.Printf("[NFT] payload.Initiator=%s payload.Owner=%s", payload.Initiator, payload.Owner)
			nftType, typeErr := parseNFTType(nftInfo.Data)
			log.Printf("[NFT] received 101 %v", nftInfo)
			log.Printf("[NFT] received nft_id=%s type=%s data=%s", nftInfo.NFTId, nftType, nftInfo.Data)
			if typeErr == nil {
				switch nftType {
				// case NFTTypeUser:
				// 	h.handleUserNFT(nftInfo)
				case NFTTypeAgent:
					h.handleAgentNFT(nftInfo)
				case NFTTypeIntent:
					// Stash the generated intentID so the /tx response hook can attach
					// provenance_req_id to the interaction rows we just inserted. Harmless
					// on non-/tx paths — only captureTxResponse (path-gated) reads it.
					if intentID, wfErr := h.handleIntentWorkflow(nftInfo); wfErr == nil && intentID != "" {
						r = r.WithContext(context.WithValue(r.Context(), ctxIntentIDKey, intentID))
					}
				}
			}
		}

		// /rubix/v1/signature carries the /tx provenance id in its request body; stash
		// it so the response hook knows which provenance rows to update.
		if r.URL.Path == rubixSignaturePath {
			var sigReq signatureRequest
			if jsonErr := json.Unmarshal(bodyBytes, &sigReq); jsonErr == nil && sigReq.ID != "" {
				fmt.Printf("test-0102 sigReq.ID=%s\n", sigReq.ID)
				r = r.WithContext(context.WithValue(r.Context(), ctxSignatureIDKey, sigReq.ID))
			}
		}
	}

	h.proxy.ServeHTTP(w, r)
}

// captureRubixResponse is the proxy ModifyResponse hook. It extracts blockchain
// transaction provenance from the /tx and /signature responses. It must never return
// an error: a capture failure is logged and the response passes through untouched.
func (h *Handler) captureRubixResponse(resp *http.Response) error {
	switch resp.Request.URL.Path {
	case rubixTxPath:
		h.captureTxResponse(resp)
	case rubixSignaturePath:
		h.captureSignatureResponse(resp)
	}
	return nil
}

// readAndRestoreBody fully reads resp.Body (so we can parse it) and puts an equivalent
// reader back so the client still receives the untouched response.
func readAndRestoreBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return body, nil
}

// captureTxResponse handles POST /rubix/v1/tx: it stores result.id as provenance_req_id
// on the intent's interaction rows, or deletes those rows if the tx failed to initiate.
func (h *Handler) captureTxResponse(resp *http.Response) {
	intentID, _ := resp.Request.Context().Value(ctxIntentIDKey).(string)
	if intentID == "" {
		return // not an intent-workflow tx we're tracking
	}

	body, err := readAndRestoreBody(resp)
	if err != nil {
		log.Printf("[provenance] tx: read body failed intent_id=%s: %v", intentID, err)
		return
	}

	var txResp txResponse
	if err := json.Unmarshal(body, &txResp); err != nil {
		log.Printf("[provenance] tx: parse failed intent_id=%s: %v", intentID, err)
		return
	}

	// status=false → the transaction failed to initiate; remove the rows we inserted
	// during request handling. (The new_intents row is left as-is by design.)
	if !txResp.Status {
		if err := h.db.DeleteInteractionsByIntent(intentID); err != nil {
			log.Printf("[provenance] tx: delete failed intent_id=%s: %v", intentID, err)
		} else {
			log.Printf("[provenance] tx: status=false, removed interaction rows intent_id=%s", intentID)
		}
		return
	}

	if txResp.Result.ID == "" {
		log.Printf("[provenance] tx: empty result.id intent_id=%s", intentID)
		return
	}
	log.Printf("[provenance] tx: updating provenance_req_id intent_id=%s req_id=%s", intentID, txResp.Result.ID)
	if err := h.db.SetProvenanceReqID(intentID, txResp.Result.ID); err != nil {
		log.Printf("[provenance] tx: set provenance_req_id failed intent_id=%s req_id=%s: %v", intentID, txResp.Result.ID, err)
		return
	}
	log.Printf("[provenance] tx: provenance_req_id updated ok intent_id=%s req_id=%s", intentID, txResp.Result.ID)
}

// captureSignatureResponse handles POST /rubix/v1/signature: it writes transactionID
// and the first childNFTId onto the rows previously tagged with provenance_req_id.
func (h *Handler) captureSignatureResponse(resp *http.Response) {
	reqID, _ := resp.Request.Context().Value(ctxSignatureIDKey).(string)
	if reqID == "" {
		return
	}
	log.Printf("[provenance] signature: received hook req_id=%s", reqID)

	body, err := readAndRestoreBody(resp)
	if err != nil {
		log.Printf("[provenance] signature: read body failed id=%s: %v", reqID, err)
		return
	}

	var sigResp signatureResponse
	if err := json.Unmarshal(body, &sigResp); err != nil {
		log.Printf("[provenance] signature: parse failed id=%s: %v", reqID, err)
		return
	}
	if !sigResp.Status {
		log.Printf("[provenance] signature: status=false id=%s, skipping", reqID)
		return
	}
	if len(sigResp.Result.MintedNFTChildren) == 0 {
		log.Printf("[provenance] signature: no mintedNFTChildren req_id=%s", reqID)
		return
	}

	childNFTId := sigResp.Result.MintedNFTChildren[0].ChildNFTId
	transactionID := sigResp.Result.TransactionID

	if childNFTId == "" {
		log.Printf("[provenance] signature: empty childNFTId req_id=%s, skipping", reqID)
		return
	}
	if transactionID == "" {
		log.Printf("[provenance] signature: empty transactionID req_id=%s, skipping", reqID)
		return
	}

	log.Printf("[provenance] signature: updating provenance_record req_id=%s transactionID=%s childNFTId=%s", reqID, transactionID, childNFTId)
	rows, err := h.db.SetProvenanceRecord(reqID, transactionID, childNFTId)
	if err != nil {
		log.Printf("[provenance] signature: update failed req_id=%s: %v", reqID, err)
		return
	}

	if rows == 0 {
		log.Printf("[provenance] signature: no rows matched provenance_req_id=%s (tx write pending?)", reqID)
		return
	}
	log.Printf("[provenance] signature: provenance_record updated ok rows=%d req_id=%s transactionID=%s childNFTId=%s",
		rows, reqID, transactionID, childNFTId)
}


func (h *Handler) handleAgentNFT(nftInfo NFTInfo) error {
	log.Printf("[agentNFT] received nft_id=%s", nftInfo.NFTId)
	data, err := parseAgentNFT(nftInfo.Data)
	if err != nil {
		return err
	}
	deployer := data.AgentMetadata.Deployer
	if deployer == "" {
		return fmt.Errorf("handleAgentNFT: missing deployer in nft_id=%s", nftInfo.NFTId)
	}
	orgID := data.AgentMetadata.OrgID
	if orgID == "" {
		return fmt.Errorf("handleAgentNFT: missing org_id in nft_id=%s", nftInfo.NFTId)
	}
	agentName := data.AgentMetadata.AgentName
	if agentName == "" {
		return fmt.Errorf("handleAgentNFT: missing agent_name in nft_id=%s", nftInfo.NFTId)
	}

	return h.db.StoreNewAgent(nftInfo.NFTId, data.AgentDID, deployer, orgID, data.Policy, agentName)
}

// handleIntentWorkflow stores the intent-workflow interactions and returns the
// generated intentID so the caller can correlate the /tx response for provenance.
func (h *Handler) handleIntentWorkflow(nftInfo NFTInfo) (string, error) {
	data, err := parseIntentWorkflow(nftInfo.Data)
	if err != nil {
		log.Printf("[intentWorkflow] failed to parse nft_id=%s: %v", nftInfo.NFTId, err)
		return "", err
	}
	if data.Envelope == nil {
		log.Printf("[intentWorkflow] envelope is nil nft_id=%s", nftInfo.NFTId)
		return "", fmt.Errorf("handleIntentWorkflow: envelope is nil")
	}

	intentID := uuid.New().String()
	orgID := h.orgID

	// All envelope nodes sorted oldest→newest.
	allEnvelopes := collectAllEnvelopes(data.Envelope)
	// Initiator is always the root envelope's From — the top-level envelope
	// (data.Envelope, newest node in the chain) — not the NFT payload's
	// initiator field.
	initiatorDID := data.Envelope.From
	initiatorName := h.resolveActorName(initiatorDID, "")

	// Build child map: parent node → its children (envelopes that list it as parent).
	// Used to derive the "to" of each node.
	childMap := map[*workflowEnvelope][]*workflowEnvelope{}
	visitedCM := map[*workflowEnvelope]bool{}
	var buildChildMap func(e *workflowEnvelope)
	buildChildMap = func(e *workflowEnvelope) {
		if e == nil || visitedCM[e] {
			return
		}
		visitedCM[e] = true
		for _, p := range e.ParentEnvelope {
			childMap[p] = append(childMap[p], e)
			buildChildMap(p)
		}
	}
	buildChildMap(data.Envelope)

	// ── Store one raw block row per envelope node ─────────────────────────────
	hashToThreatID := map[string]string{} // envelope hash → threat ID, for linking interactions
	for idx, env := range allEnvelopes {
		// Derive to: first child's From, or initiatorDID for root if different.
		var toDID string
		if children := childMap[env]; len(children) > 0 {
			toDID = children[0].From
		} else if env.From != initiatorDID {
			toDID = initiatorDID
		}

		rawJSON, _ := json.Marshal(env)
		msg := extractPayloadText(env.Payload)
		threat := env.Code != 0 && env.Code != 1000

		blockID := fmt.Sprintf("%s-block-%d", intentID, idx)
		blockRec := &db.IntentBlockRecord{
			ID:             blockID,
			IntentID:       intentID,
			BlockIndex:     idx,
			AgentDID:       env.From,
			AgentName:      h.resolveActorName(env.From, ""),
			Message:        msg,
			Signature:      env.Signature,
			ThreatDetected: threat,
			TrustIssues:    []string{},
			CreatedAt:      time.Unix(env.Epoch, 0).UTC(),
			FromDID:        env.From,
			ToDID:          toDID,
			RawData:        json.RawMessage(rawJSON),
		}
		if err := h.db.StoreIntentBlockData(blockRec); err != nil {
			log.Printf("[intentWorkflow] block data save error idx=%d: %v", idx, err)
		}

		// If this envelope signals a threat, resolve the message and store it.
		if threat {
			var threatMsg string
			if env.Code >= 2000 && env.Code < 3000 {
				// COCA codes — use the threat title as the message (no external call).
				if rec, err := h.db.GetThreatCodeDetail(env.Code); err == nil {
					threatMsg = rec.Title
				}
			} else if env.Code >= 3000 && env.Hash != "" {
				// CBAC/guard codes — fetch the detailed reason from the cbac-decisions service.
				threatMsg = h.fetchCbacDecisionReason(env.Hash)
			}
			threatID := fmt.Sprintf("%s-threat-%d", intentID, idx)
			if err := h.db.StoreThreat(threatID, intentID, blockID, env.Code, threatMsg, time.Unix(env.Epoch, 0).UTC()); err != nil {
				log.Printf("[intentWorkflow] StoreThreat idx=%d code=%d: %v", idx, env.Code, err)
			} else {
				log.Printf("[intentWorkflow] threat stored idx=%d code=%d msg=%q", idx, env.Code, threatMsg)
				if env.Hash != "" {
					hashToThreatID[env.Hash] = threatID
				}
			}
		}
	}

	// ── Extract interactions from DAG edges ──────────────────────────────────
	rawInteractions := extractInteractionsFromEnvelopes(data.Envelope, initiatorDID)

	// Deduplicate: drop only when hash + from + to are all identical.
	type dedupKey struct{ hash, from, to string }
	seenKey := map[dedupKey]bool{}
	interactions := rawInteractions[:0]
	for _, ix := range rawInteractions {
		k := dedupKey{ix.Hash, ix.FromDID, ix.ToDID}
		if ix.Hash != "" && seenKey[k] {
			log.Printf("[intentWorkflow] dropping duplicate hash=%s from=%s to=%s", ix.Hash, ix.FromDID, ix.ToDID)
			continue
		}
		if ix.Hash != "" {
			seenKey[k] = true
		}
		interactions = append(interactions, ix)
	}

	// Resolve display names.
	for i, ix := range interactions {
		interactions[i].FromName = h.resolveActorName(ix.FromDID, ix.FromName)
		interactions[i].ToName = h.resolveActorName(ix.ToDID, ix.ToName)
	}

	log.Printf("[intentWorkflow] parsed ok — dag_envelopes=%d interactions=%d initiator=%s intentID=%s orgID=%s",
		len(allEnvelopes), len(interactions), initiatorDID, intentID, orgID)

	// ── Ensure actors exist in the correct tables ────────────────────────────
	seenDIDs := map[string]bool{}
	for _, ix := range interactions {
		for _, did := range []string{ix.FromDID, ix.ToDID} {
			if did == "" || seenDIDs[did] {
				continue
			}
			seenDIDs[did] = true
			name := h.resolveActorName(did, "")
			// Already a known user — skip.
			if uname, err := h.db.GetOrgUserNameByDID(did); err == nil && uname != "" {
				log.Printf("[intentWorkflow] did=%s is a user, skipping", did)
				continue
			}
			// Already a known agent — skip.
			if agent, err := h.db.GetAgentInfo(did); err == nil && agent.AgentDID != "" {
				log.Printf("[intentWorkflow] did=%s is already an agent, skipping", did)
				continue
			}
			// Found in new_tools table — skip (registered tool/app).
			if h.db.IsNewTool(did) {
				log.Printf("[intentWorkflow] did=%s is a registered tool, skipping", did)
				continue
			}
			// Unknown DID — store as agent.
			if err := h.db.StoreNewAgent(uuid.New().String(), did, initiatorDID, orgID, "", name); err != nil {
				log.Printf("[intentWorkflow] StoreNewAgent did=%s: %v", did, err)
			} else {
				log.Printf("[intentWorkflow] new agent stored did=%s name=%s", did, name)
			}
		}
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
		eventTime := time.Unix(ix.Epoch, 0).UTC()
		threatID := hashToThreatID[ix.Hash]
		if err := h.db.StoreNewInteraction(
			iid, ix.FromDID, ix.FromName, ix.ToDID, ix.ToName, ix.Type, "", ix.Threat, intentID, orgID, ix.Message, ix.Signature, threatID, eventTime,
		); err != nil {
			return "", fmt.Errorf("handleIntentWorkflow: StoreNewInteraction: %v", err)
		}
		log.Printf("[intentWorkflow] interaction[%d] from=%s to=%s type=%s threat=%v", idx, ix.FromDID, ix.ToDID, ix.Type, ix.Threat)
	}

	// ── Store intent ─────────────────────────────────────────────────────────
	flowType := detectFlowTypeFromExtracts(interactions)
	executor := initiatorName
	if executor == "" {
		executor = initiatorDID
	}
	if err := h.db.StoreIntent(intentID, initiatorDID, orgID, flowType, executor, len(allEnvelopes), threatDetected, interactionIDs); err != nil {
		log.Printf("[intentWorkflow] intent save error: %v", err)
		return "", err
	}
	log.Printf("[intentWorkflow] saved intent_id=%s interactions=%d threat=%v flowType=%s", intentID, len(interactionIDs), threatDetected, flowType)
	return intentID, nil
}

func (h *Handler) handleIntentNFT(nftInfo NFTInfo) error {
	log.Printf("[intentNFT] received nft_id=%s", nftInfo.NFTId)

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
	orgID := h.orgID

	initiatorDID := ""
	if len(blocks) > 0 {
		initiatorDID = blocks[0].Agent
	}

	log.Printf("[intentNFT] blocks=%d org=%s initiator=%s", len(blocks), orgID, initiatorDID)
	// ── 4. Ensure agents exist ───────────────────────────────────────────────
	for _, b := range blocks {
		agentName := b.Name
		if agentName == "" {
			log.Printf("[intentNFT] skipping agent with no name did=%s", b.Agent)
			continue
		}
		if err := h.db.StoreNewAgent(uuid.New().String(), b.Agent, initiatorDID, orgID, "", agentName); err != nil {
			log.Printf("[intentNFT] agent save error did=%s: %v", b.Agent, err)
		} else {
			log.Printf("[intentNFT] agent saved did=%s name=%s org=%s", b.Agent, agentName, orgID)
		}
	}

	// ── 5. Store interactions ────────────────────────────────────────────────
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
			iid, ix.FromDID, ix.FromName, ix.ToDID, ix.ToName, ix.Type, ix.Direction, ix.Threat, intentID, orgID, ix.Message, ix.Signature, "", time.Time{},
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
	type blockActor struct {
		DID  string `json:"did"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	type blockOut struct {
		ID             string     `json:"id"`
		BlockIndex     int        `json:"block_index"`
		BlockType      string     `json:"block_type"`
		From           blockActor `json:"from"`
		To             blockActor `json:"to"`
		Message        string     `json:"message"`
		Signature      string     `json:"signature"`
		ThreatDetected bool       `json:"threat_detected"`
		TrustIssues    []string   `json:"trust_issues"`
		CreatedAt      string     `json:"created_at"`
		ParentBlock    *blockOut  `json:"parent_block"`
	}
	// Build nested structure: blocks[0] is innermost (no parent), each successive
	// block wraps the previous as parent_block, outermost (latest) is the root.
	var root *blockOut
	for _, b := range blocks {
		issues := b.TrustIssues
		if issues == nil {
			issues = []string{}
		}
		node := &blockOut{
			ID:         b.ID,
			BlockIndex: b.BlockIndex,
			BlockType:  b.BlockType,
			From: blockActor{
				DID:  b.FromDID,
				Name: b.FromName,
				Type: b.FromType,
			},
			To: blockActor{
				DID:  b.ToDID,
				Name: b.ToName,
				Type: b.ToType,
			},
			Message:        b.Message,
			Signature:      b.Signature,
			ThreatDetected: b.ThreatDetected,
			TrustIssues:    issues,
			CreatedAt:      b.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			ParentBlock:    root,
		}
		root = node
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: root})
}

func (h *Handler) GetIntentRawData(c *gin.Context) {
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
	type blockRaw struct {
		BlockIndex int             `json:"block_index"`
		RawData    json.RawMessage `json:"raw_data"`
	}
	result := make([]blockRaw, 0, len(blocks))
	for _, b := range blocks {
		raw := b.RawData
		if len(raw) == 0 {
			raw = json.RawMessage("{}")
		}
		result = append(result, blockRaw{BlockIndex: b.BlockIndex, RawData: raw})
	}
	c.JSON(http.StatusOK, Response{Status: true, Data: result})
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
		OTP      string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" || req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "email, password and orgID are required"})
		return
	}
	if req.OTP == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "otp is required"})
		return
	}
	if !h.verifyOTP(req.Email, req.OTP) {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid or expired OTP"})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}



	if err := h.db.StoreOrgUser( req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
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
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to hash password"})
		return
	}

	if err := h.db.StoreOrgUser(req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create user: %v", err)})
		return
	}

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
		OTP      string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "username, email and password are required"})
		return
	}
	if req.OrgID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "orgID is required"})
		return
	}
	if req.OTP == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "otp is required"})
		return
	}
	if !h.verifyOTP(req.Email, req.OTP) {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid or expired OTP"})
		return
	}

	// Call external agent service to register admin and get DID.
	log.Printf("[CreateAdmin] calling agent service username=%q orgID=%q email=%q", req.Username, req.OrgID, req.Email)
	did, err := h.callRegisterAdmin(req.Username, req.OrgID, req.Email, req.Password)
	if err != nil {
		log.Printf("[CreateAdmin] agent service error: %v", err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agent service error: %v", err)})
		return
	}
	log.Printf("[CreateAdmin] agent service returned did=%q", did)

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
	did := c.GetString(CtxDID)
	if did == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}
	profile, err := h.db.GetAdminProfile(did)
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

	isAdmin := c.GetBool(CtxIsAdmin)
	userDID := c.GetString(CtxDID)

	var metrics *db.OrgMetrics
	var agents []*db.AgentVolumeRecord
	var err error

	if isAdmin {
		metrics, err = h.db.GetOrgMetrics(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch metrics: %v", err)})
			return
		}
		agents, err = h.db.GetTopAgentsByOrg(orgID, 5, 0)
	} else {
		metrics, err = h.db.GetUserMetrics(userDID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch metrics: %v", err)})
			return
		}
		agents, err = h.db.GetTopAgentsByUser(userDID, orgID, 5, 0)
	}
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
			"flowEnabled":       metrics.AgentCount > 0,
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

	isAdmin := c.GetBool(CtxIsAdmin)
	userDID := c.GetString(CtxDID)
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
	} else if isAdmin {
		total, err = h.db.CountInteractionsByOrg(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
			return
		}
		interactions, err = h.db.GetInteractionsByOrg(orgID, pageSize, offset)
	} else {
		total, err = h.db.CountInteractionsByUser(userDID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
			return
		}
		interactions, err = h.db.GetInteractionsByUser(userDID, orgID, pageSize, offset)
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
			"threatID":      i.ThreatID,
			"intentID":      i.IntentID,
			"time":          i.Time,
			"message":       i.Message,
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

	isAdmin := c.GetBool(CtxIsAdmin)
	userDID := c.GetString(CtxDID)

	var total int
	var threats []*db.InteractionRecord
	var err error

	if isAdmin {
		total, err = h.db.CountThreatsByOrg(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count threats: %v", err)})
			return
		}
		threats, err = h.db.GetThreatsByOrg(orgID, pageSize, offset)
	} else {
		total, err = h.db.CountThreatsByUser(userDID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count threats: %v", err)})
			return
		}
		threats, err = h.db.GetThreatsByUser(userDID, orgID, pageSize, offset)
	}
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
			"threat":        t.Threat,
			"threatID":      t.ThreatID,
			"intentID":      t.IntentID,
			"time":          t.Time,
			"message":       t.Message,
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

func (h *Handler) AgentsAppsMetrics(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	data, err := h.db.GetAgentsAppsMetrics(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: err.Error()})
		return
	}

	type agentOut struct {
		Name              string `json:"name"`
		TotalInteractions int    `json:"totalInteractions"`
		TotalThreats      int    `json:"totalThreats"`
	}
	type appOut struct {
		Name              string `json:"name"`
		TotalInteractions int    `json:"totalInteractions"`
		TotalThreats      int    `json:"totalThreats"`
	}

	agents := make([]agentOut, 0, len(data.TopAgents))
	for _, a := range data.TopAgents {
		agents = append(agents, agentOut{
			Name:              a.AgentName,
			TotalInteractions: a.TotalInteractions,
			TotalThreats:      a.TotalThreats,
		})
	}
	apps := make([]appOut, 0, len(data.TopApps))
	for _, a := range data.TopApps {
		apps = append(apps, appOut{
			Name:              a.Name,
			TotalInteractions: a.TotalInteractions,
			TotalThreats:      a.TotalThreats,
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"topAgents": agents,
			"topApps":   apps,
			"metrics": gin.H{
				"totalInteractions": data.TotalInteractions,
				"totalThreats":      data.TotalThreats,
				"totalAgents":       data.TotalAgents,
				"totalApps":         data.TotalApps,
				"avgReliability":    data.AvgReliability,
			},
		},
	})
}

func (h *Handler) Search(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "q is required"})
		return
	}

	orgID := c.GetString(CtxOrgID)
	results, err := h.db.Search(q, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: err.Error()})
		return
	}

	type agentOut struct {
		DID   string `json:"did"`
		Name  string `json:"name"`
		OrgID string `json:"orgID"`
	}
	type appOut struct {
		DID  string `json:"did"`
		Name string `json:"name"`
	}
	type intentOut struct {
		IntentID       string `json:"intentID"`
		FlowType       string `json:"flowType"`
		Status         string `json:"status"`
		ThreatDetected bool   `json:"threatDetected"`
		StartedAt      string `json:"startedAt"`
	}

	agents := make([]agentOut, 0, len(results.Agents))
	for _, a := range results.Agents {
		agents = append(agents, agentOut{DID: a.DID, Name: a.Name, OrgID: a.OrgID})
	}
	apps := make([]appOut, 0, len(results.Apps))
	for _, a := range results.Apps {
		apps = append(apps, appOut{DID: a.DID, Name: a.Name})
	}
	intents := make([]intentOut, 0, len(results.Intents))
	for _, i := range results.Intents {
		intents = append(intents, intentOut{
			IntentID:       i.IntentID,
			FlowType:       i.FlowType,
			Status:         i.Status,
			ThreatDetected: i.ThreatDetected,
			StartedAt:      i.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"agents":  agents,
			"apps":    apps,
			"intents": intents,
		},
	})
}

func (h *Handler) InteractionSeries(c *gin.Context) {
	orgID := c.GetString(CtxOrgID)
	rangeParam := c.DefaultQuery("range", "24h")
	if rangeParam != "24h" && rangeParam != "7d" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "range must be 24h or 7d"})
		return
	}

	buckets, err := h.db.GetInteractionSeries(orgID, rangeParam)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to fetch series"})
		return
	}

	safe := make([]int, len(buckets))
	threats := make([]int, len(buckets))
	for i, b := range buckets {
		safe[i] = b.Safe
		threats[i] = b.Threats
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"safe":    safe,
			"threats": threats,
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

	isAdmin := c.GetBool(CtxIsAdmin)
	userDID := c.GetString(CtxDID)

	log.Printf("[IntentList] isAdmin=%v userDID=%q orgID=%q page=%d", isAdmin, userDID, orgID, page)

	var total int
	var intents []*db.IntentRecord
	var err error

	if isAdmin {
		total, err = h.db.CountIntentsByOrg(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
			return
		}
		intents, err = h.db.GetIntentsByOrg(orgID, pageSize, offset)
	} else {
		if userDID == "" {
			log.Printf("[IntentList] userDID is empty — user will see 0 intents")
		}
		total, err = h.db.CountIntentsByUser(userDID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
			return
		}
		log.Printf("[IntentList] user query returned total=%d for userDID=%q orgID=%q", total, userDID, orgID)
		intents, err = h.db.GetIntentsByUser(userDID, orgID, pageSize, offset)
	}
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

	isAdmin := c.GetBool(CtxIsAdmin)
	userDID := c.GetString(CtxDID)

	log.Printf("[AgentsList] isAdmin=%v userDID=%q orgID=%q", isAdmin, userDID, orgID)

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	var (
		total  int
		agents []*db.AgentDetailRecord
		err    error
	)

	if isAdmin {
		total, err = h.db.CountAgentsByOrg(orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count agents: %v", err)})
			return
		}
		agents, err = h.db.GetAgentsByOrg(orgID, pageSize, offset)
	} else {
		total, err = h.db.CountAgentsByUser(userDID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count agents: %v", err)})
			return
		}
		agents, err = h.db.GetAgentsByUser(userDID, orgID, pageSize, offset)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch agents: %v", err)})
		return
	}

	log.Printf("[AgentsList] total=%d returned=%d", total, len(agents))
	for _, a := range agents {
		log.Printf("[AgentsList] agent did=%q name=%q deployer=%q", a.AgentDID, a.AgentName, a.DeployerDID)
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
			"threatID":      i.ThreatID,
			"intentID":      i.IntentID,
			"time":          i.Time,
			"message":       i.Message,
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
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing auth context"})
		return
	}

	const pageSize = 10
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := h.db.CountIntentsByUser(userDID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
		return
	}

	intents, err := h.db.GetIntentsByUser(userDID, orgID, pageSize, offset)
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

func firstNWords(s string, n int) string {
	words := strings.Fields(s)
	if len(words) <= n {
		return s
	}
	return strings.Join(words[:n], " ") + "..."
}

func buildIntentList(intents []*db.IntentRecord) []gin.H {
	list := make([]gin.H, 0, len(intents))
	for _, i := range intents {
		entry := gin.H{
			"intentID":           i.IntentID,
			"title":              firstNWords(i.Title, 5),
			"initiatorDID":       i.InitiatorDID,
			"initiatorName":      i.InitiatorName,
			"startedAt":          i.StartedAt,
			"status":             i.Status,
			"threatDetected":     i.ThreatDetected,
			"flowType":           i.FlowType,
			"executor":           i.Executor,
			"chainDepth":         i.ChainDepth,
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

	type interactionOut struct {
		InteractionID      string `json:"interactionID"`
		Initiator          string `json:"initiator"`
		InitiatorName      string `json:"initiatorName"`
		To                 string `json:"to"`
		ToName             string `json:"toName"`
		Type               string `json:"type"`
		Message            string `json:"message"`
		IntentID           string `json:"intentID"`
		Threat             bool   `json:"threat"`
		ThreatID           string `json:"threatID"`
		Epoch              int64  `json:"epoch"`
		Signature          string `json:"signature"`
		ProvenanceReqID    string `json:"provenanceReqID"`
		ProvenanceRecordID string `json:"provenanceRecordID"`
	}

	list := make([]interactionOut, 0, len(interactions))
	for _, ix := range interactions {
		list = append(list, interactionOut{
			InteractionID:      ix.InteractionID,
			Initiator:          ix.From,
			InitiatorName:      ix.FromName,
			To:                 ix.To,
			ToName:             ix.ToName,
			Type:               ix.Type,
			Message:            ix.Message,
			IntentID:           ix.IntentID,
			Threat:             ix.Threat,
			ThreatID:           ix.ThreatID,
			Epoch:              ix.Time.Unix(),
			Signature:          ix.Signature,
			ProvenanceReqID:    ix.ProvenanceReqID,
			ProvenanceRecordID: ix.ProvenanceRecordID,
		})
	}

	basicInfo := gin.H{
		"intentID":          intent.IntentID,
		"initiatorDID":      intent.InitiatorDID,
		"initiatorName":     intent.InitiatorName,
		"flowType":          intent.FlowType,
		"status":            intent.Status,
		"threatDetected":    intent.ThreatDetected,
		"chainDepth":        intent.ChainDepth,
		"interactionsCount": intent.InteractionsCount,
		"agentsCount":       intent.AgentsCount,
		"toolsCount":        intent.ToolsCount,
		"startedAt":         intent.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"basicInfo":    basicInfo,
			"interactions": list,
		},
	})
}

func (h *Handler) UpdateProfile(c *gin.Context) {
	var req struct {
		Name  *string `json:"name,omitempty"`
		Email *string `json:"email,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid request body"})
		return
	}
	if req.Name == nil && req.Email == nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "name or email is required"})
		return
	}

	callerEmail := c.GetString(CtxEmail)
	isAdmin := c.GetBool(CtxIsAdmin)

	if req.Name != nil {
		var err error
		if isAdmin {
			err = h.db.UpdateAdminName(callerEmail, *req.Name)
		} else {
			err = h.db.UpdateUserName(callerEmail, *req.Name)
		}
		if err != nil {
			log.Printf("[UpdateProfile] update name email=%s err=%v", callerEmail, err)
			c.JSON(http.StatusBadRequest, Response{Status: false, Message: err.Error()})
			return
		}
	}

	if req.Email != nil {
		if *req.Email == "" {
			c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid email format"})
			return
		}
		var err error
		if isAdmin {
			err = h.db.UpdateAdminEmail(callerEmail, *req.Email)
		} else {
			err = h.db.UpdateUserEmail(callerEmail, *req.Email)
		}
		if err != nil {
			log.Printf("[UpdateProfile] update email from=%s to=%s err=%v", callerEmail, *req.Email, err)
			c.JSON(http.StatusBadRequest, Response{Status: false, Message: err.Error()})
			return
		}
	}

	log.Printf("[UpdateProfile] profile updated email=%s isAdmin=%v", callerEmail, isAdmin)
	c.JSON(http.StatusOK, Response{Status: true, Message: "Profile updated successfully"})
}

func (h *Handler) AppRegistration(c *gin.Context) {
	var req struct {
		ToolName string `json:"tool_name"`
		ToolID   string `json:"tool_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ToolName == "" || req.ToolID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "tool_name and tool_id are required"})
		return
	}
	if err := h.db.StoreNewTool(req.ToolID, req.ToolName, "AGENT_DNA_BETA"); err != nil {
		log.Printf("[AppRegistration] db error tool_id=%s err=%v", req.ToolID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "failed to register app"})
		return
	}
	log.Printf("[AppRegistration] registered app tool_id=%s tool_name=%s", req.ToolID, req.ToolName)
	c.JSON(http.StatusOK, Response{Status: true, Message: "app registered successfully"})
}

func (h *Handler) RevokeAgent(c *gin.Context) {
	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		AgentDID string `json:"agent_did" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentDID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "agent_did is required"})
		return
	}

	// Mark revoked in DB.
	if err := h.db.RevokeAgent(req.AgentDID); err != nil {
		log.Printf("[RevokeAgent] db error agent_did=%s err=%v", req.AgentDID, err)
		c.JSON(http.StatusNotFound, Response{Status: false, Message: err.Error()})
		return
	}

	// Call admin server to flip is_active = false on the agent.
	endpoint := h.adminServiceURL + "agent-admin/v1/revoke-agent"
	b, _ := json.Marshal(map[string]string{"agent_id": req.AgentDID})
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[RevokeAgent] admin server http error agent_did=%s err=%v", req.AgentDID, err)
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to reach admin server: %v", err)})
		return
	}
	defer resp.Body.Close()

	var adminResp struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	rawBody, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(rawBody, &adminResp); err != nil {
		log.Printf("[RevokeAgent] failed to parse admin server response agent_did=%s body=%s", req.AgentDID, string(rawBody))
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: "invalid response from admin server"})
		return
	}
	if !adminResp.Status {
		log.Printf("[RevokeAgent] admin server rejected revocation agent_did=%s message=%s", req.AgentDID, adminResp.Message)
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: adminResp.Message})
		return
	}

	log.Printf("[RevokeAgent] agent revoked agent_did=%s", req.AgentDID)
	c.JSON(http.StatusOK, Response{Status: true, Message: adminResp.Message})
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

	interactedApps, err := h.db.GetAgentInteractedApps(agentDID)
	if err != nil {
		log.Printf("[AgentInfo] failed to fetch interacted apps agentDID=%s err=%v", agentDID, err)
		interactedApps = []string{}
	}
	if interactedApps == nil {
		interactedApps = []string{}
	}

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
			"appsInteracted":    len(interactedApps),
			"appsList":          interactedApps,
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

	provenanceRecordID := ""
	txns := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		if provenanceRecordID == "" && i.ProvenanceRecordID != "" {
			provenanceRecordID = i.ProvenanceRecordID
		}
		txns = append(txns, gin.H{
			"interactionID":      i.InteractionID,
			"from":               i.From,
			"fromName":           i.FromName,
			"to":                 i.To,
			"toName":             i.ToName,
			"type":               i.Type,
			"direction":          i.Direction,
			"threat":             i.Threat,
			"threatID":           i.ThreatID,
			"time":               i.Time,
			"message":            i.Message,
			"signature":          i.Signature,
			"provenanceReqID":    i.ProvenanceReqID,
			"provenanceRecordID": i.ProvenanceRecordID,
		})
	}

	data := gin.H{
		"intentID":           intent.IntentID,
		"initiatorDID":       intent.InitiatorDID,
		"initiatorName":      intent.InitiatorName,
		"startedAt":          intent.StartedAt,
		"status":             intent.Status,
		"threatDetected":     intent.ThreatDetected,
		"flowType":           intent.FlowType,
		"executor":           intent.Executor,
		"chainDepth":         intent.ChainDepth,
		"interactionsCount":  intent.InteractionsCount,
		"agentsCount":        intent.AgentsCount,
		"toolsCount":         intent.ToolsCount,
		"firstInteractionAt": intent.FirstInteractionAt,
		"lastInteractionAt":  intent.LastInteractionAt,
		"runtimeSeconds":     intent.RuntimeSeconds,
		"provenanceRecordID": provenanceRecordID,
		"interactions":       txns,
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

func agentStatus(score float64, totalInteractions int) string {
	if totalInteractions == 0 {
		return "inactive"
	}
	if score >= 80 {
		return "active"
	}
	if score >= 50 {
		return "warn"
	}
	return "inactive"
}

func (h *Handler) UserInfo(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)

	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "userID is required"})
		return
	}

	const pageSize = 10

	interactionsPage := 1
	if p, err := strconv.Atoi(c.Query("interactionsPage")); err == nil && p > 0 {
		interactionsPage = p
	}
	intentsPage := 1
	if p, err := strconv.Atoi(c.Query("intentsPage")); err == nil && p > 0 {
		intentsPage = p
	}
	threatsPage := 1
	if p, err := strconv.Atoi(c.Query("threatsPage")); err == nil && p > 0 {
		threatsPage = p
	}
	agentsPage := 1
	if p, err := strconv.Atoi(c.Query("agentsPage")); err == nil && p > 0 {
		agentsPage = p
	}

	user, err := h.db.GetUserDetail(userID, orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "user not found"})
		return
	}

	// Interactions
	totalInteractions, _ := h.db.CountInteractionsByUser(userID, orgID)
	interactions, err := h.db.GetInteractionsByUser(userID, orgID, pageSize, (interactionsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("interactions: %v", err)})
		return
	}
	interactionList := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		interactionList = append(interactionList, gin.H{
			"interactionID":      i.InteractionID,
			"from":               i.From,
			"fromName":           i.FromName,
			"to":                 i.To,
			"toName":             i.ToName,
			"type":               i.Type,
			"threat":             i.Threat,
			"threatID":           i.ThreatID,
			"intentID":           i.IntentID,
			"message":            i.Message,
			"signature":          i.Signature,
			"provenanceRecordID": i.ProvenanceRecordID,
			"time":               i.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}

	// Intents
	totalIntents, _ := h.db.CountUserIntents(userID, orgID)
	intents, err := h.db.GetUserIntents(userID, orgID, pageSize, (intentsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("intents: %v", err)})
		return
	}

	// Threats
	totalThreats, _ := h.db.CountThreatsByUser(userID, orgID)
	threats, err := h.db.GetThreatsByUser(userID, orgID, pageSize, (threatsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("threats: %v", err)})
		return
	}
	threatList := make([]gin.H, 0, len(threats))
	for _, i := range threats {
		threatList = append(threatList, gin.H{
			"interactionID":      i.InteractionID,
			"from":               i.From,
			"fromName":           i.FromName,
			"to":                 i.To,
			"toName":             i.ToName,
			"type":               i.Type,
			"threat":             i.Threat,
			"intentID":           i.IntentID,
			"message":            i.Message,
			"signature":          i.Signature,
			"provenanceRecordID": i.ProvenanceRecordID,
			"time":               i.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}

	// Owned agents
	totalAgents, _ := h.db.CountAgentsByOwner(userID, orgID)
	agents, err := h.db.GetAgentsByOwner(userID, orgID, pageSize, (agentsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("agents: %v", err)})
		return
	}
	agentList := make([]gin.H, 0, len(agents))
	for _, a := range agents {
		agentList = append(agentList, gin.H{
			"agentDID":          a.AgentDID,
			"agentName":         a.AgentName,
			"status":            agentStatus(a.Score, a.TotalInteractions),
			"created":           a.CreatedAt.Unix(),
			"totalInteractions": a.TotalInteractions,
			"totalThreats":      a.TotalThreats,
		})
	}

	var lastActive interface{}
	if user.LastActive != nil {
		lastActive = user.LastActive.UTC().Format(time.RFC3339)
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"user": gin.H{
				"userID":              user.UserDID,
				"userName":            user.UserName,
				"displayName":         user.DisplayName,
				"createdAt":           user.CreatedAt.UTC().Format(time.RFC3339),
				"lastActive":          lastActive,
				"isActive":            user.IsActive,
				"accessAgentCount":    user.AccessAgentCount,
				"totalInteractions":   user.TotalInteractions,
				"totalThreats":        user.TotalThreats,
				"totalIntents":        user.TotalIntents,
				"totalAgentsDeployed": user.TotalAgentsOwned,
			},
			"interactions": gin.H{
				"list":       interactionList,
				"total":      totalInteractions,
				"page":       interactionsPage,
				"pageSize":   pageSize,
				"totalPages": (totalInteractions + pageSize - 1) / pageSize,
			},
			"intents": gin.H{
				"list":       buildIntentList(intents),
				"total":      totalIntents,
				"page":       intentsPage,
				"pageSize":   pageSize,
				"totalPages": (totalIntents + pageSize - 1) / pageSize,
			},
			"threats": gin.H{
				"list":       threatList,
				"total":      totalThreats,
				"page":       threatsPage,
				"pageSize":   pageSize,
				"totalPages": (totalThreats + pageSize - 1) / pageSize,
			},
			"agents": gin.H{
				"list":       agentList,
				"total":      totalAgents,
				"page":       agentsPage,
				"pageSize":   pageSize,
				"totalPages": (totalAgents + pageSize - 1) / pageSize,
			},
		},
	})
}

func (h *Handler) ToolInfo(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	orgID := c.GetString(CtxOrgID)

	// Accept either ?toolDID= or ?name= — whichever is provided.
	query := c.Query("toolDID")
	if query == "" {
		query = c.Query("name")
	}
	if query == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "toolDID or name is required"})
		return
	}

	tool, err := h.db.GetToolByNameOrDID(query, orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "tool not found"})
		return
	}

	const pageSize = 10

	interactionsPage := 1
	if p, err := strconv.Atoi(c.Query("interactionsPage")); err == nil && p > 0 {
		interactionsPage = p
	}
	intentsPage := 1
	if p, err := strconv.Atoi(c.Query("intentsPage")); err == nil && p > 0 {
		intentsPage = p
	}

	// Interactions
	totalInteractions, err := h.db.CountInteractionsByTool(tool.DID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count interactions: %v", err)})
		return
	}
	interactions, err := h.db.GetInteractionsByTool(tool.DID, orgID, pageSize, (interactionsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch interactions: %v", err)})
		return
	}
	interactionList := make([]gin.H, 0, len(interactions))
	for _, i := range interactions {
		interactionList = append(interactionList, gin.H{
			"interactionID":      i.InteractionID,
			"from":               i.From,
			"fromName":           i.FromName,
			"to":                 i.To,
			"toName":             i.ToName,
			"type":               i.Type,
			"threat":             i.Threat,
			"threatID":           i.ThreatID,
			"intentID":           i.IntentID,
			"message":            i.Message,
			"signature":          i.Signature,
			"provenanceRecordID": i.ProvenanceRecordID,
			"time":               i.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}

	// Intents
	totalIntents, err := h.db.CountIntentsByTool(tool.DID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count intents: %v", err)})
		return
	}
	intents, err := h.db.GetIntentsByTool(tool.DID, orgID, pageSize, (intentsPage-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch intents: %v", err)})
		return
	}

	c.JSON(http.StatusOK, Response{
		Status: true,
		Data: gin.H{
			"toolDID":           tool.DID,
			"toolName":          tool.Name,
			"totalInteractions": tool.TotalInteractions,
			"totalThreats":      tool.TotalThreats,
			"totalIntents":      tool.TotalIntents,
			"totalAgents":       tool.TotalAgents,
			"score":             tool.Score,
			"lastInteractedAt":  tool.LastInteractedAt,
			"interactions": gin.H{
				"list":       interactionList,
				"total":      totalInteractions,
				"page":       interactionsPage,
				"pageSize":   pageSize,
				"totalPages": (totalInteractions + pageSize - 1) / pageSize,
			},
			"intents": gin.H{
				"list":       buildIntentList(intents),
				"total":      totalIntents,
				"page":       intentsPage,
				"pageSize":   pageSize,
				"totalPages": (totalIntents + pageSize - 1) / pageSize,
			},
		},
	})
}

// callRegisterAdmin calls the external agent service to register an admin and get their DID.
func (h *Handler) callRegisterAdmin(username, org, email, password string) (string, error) {
	endpoint := h.createAgentEndpoint + "agent-admin/v1/register-admin"
	log.Printf("[callRegisterAdmin] POST %s username=%q org=%q email=%q", endpoint, username, org, email)

	b, _ := json.Marshal(map[string]string{"username": username, "org": org, "email": email, "password": password})
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[callRegisterAdmin] http error: %v", err)
		return "", fmt.Errorf("callRegisterAdmin: http post: %v", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	log.Printf("[callRegisterAdmin] status=%d body=%s", resp.StatusCode, string(rawBody))

	var result struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rawBody, &result); err != nil {
		log.Printf("[callRegisterAdmin] failed to parse response: %v", err)
		return "", fmt.Errorf("callRegisterAdmin: parse response: %v", err)
	}

	if !result.Status {
		log.Printf("[callRegisterAdmin] agent service returned failure: %s", result.Message)
		return "", fmt.Errorf("register admin failed: %s", result.Message)
	}
	log.Printf("[callRegisterAdmin] success did=%s", result.Message)
	return result.Message, nil // message = admin DID on success
}

// callCreateAgent POSTs multipart form-data to CREATE_AGENT_ENDPOINT.
// The agent DID is known upfront; the API returns the NFT ID for that agent.
func (h *Handler) callCreateAgent(agentName, policy, creatorDID, orgID, agentDID string) (nftID string, err error) {
	if policy == "" {
		policy = "default policy"
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("creator_did", creatorDID)
	mw.WriteField("org_id", orgID)
	mw.WriteField("agent_name", agentName)
	mw.WriteField("agent_id", agentDID)
	fw, fwErr := mw.CreateFormFile("policy", "policy.txt")
	if fwErr != nil {
		return "", fmt.Errorf("callCreateAgent: create form file: %v", fwErr)
	}
	if _, fwErr = fw.Write([]byte(policy)); fwErr != nil {
		return "", fmt.Errorf("callCreateAgent: write policy: %v", fwErr)
	}
	mw.Close()

	endpoint := h.createAgentEndpoint + "agent-admin/v1/create-agent"
	resp, err := http.Post(endpoint, mw.FormDataContentType(), &buf)
	if err != nil {
		return "", fmt.Errorf("callCreateAgent: http post: %v", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	log.Printf("[callCreateAgent] response status=%d body=%s", resp.StatusCode, string(rawBody))

	var result struct {
		Status      bool   `json:"status"`
		Message     string `json:"message"`
		AgentID     string `json:"agent_id"`
		AgentCardID string `json:"agent_card_id"`
	}
	json.Unmarshal(rawBody, &result)

	if !result.Status {
		return "", fmt.Errorf("create agent failed: %s", result.Message)
	}
	return result.AgentCardID, nil
}

// callUpdateAgent POSTs multipart form-data to UPDATE_AGENT_ENDPOINT.
func (h *Handler) callUpdateAgent(agentName, agentID, policy, adminDID, orgID string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	mw.WriteField("creator_did", adminDID)
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
	if err := h.callUpdateAgent(agentInfo.AgentName, agentDID, content, c.GetString(CtxDID), orgID); err != nil {
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
	Initiator     string
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
			Initiator     string `json:"initiator"`
			Epoch         int64  `json:"epoch"`
			Data          string `json:"data"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chainResp); err != nil {
		return nil, err
	}

	if len(chainResp.Result) <= 0 {
		return nil, nil
	}

	var out []struct {
		TransactionID string
		Initiator     string
		Epoch         int64
		Data          string
	}
	for _, e := range chainResp.Result {
		out = append(out, struct {
			TransactionID string
			Initiator     string
			Epoch         int64
			Data          string
		}{e.TransactionID, e.Initiator, e.Epoch, e.Data})
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

	if agentID != "" {
		if exists, err := h.db.ActiveRequestExistsForAgent(agentID); err != nil {
			log.Printf("[AgentsCreationRequestsCreate] ActiveRequestExistsForAgent check failed agentID=%q err=%v", agentID, err)
		} else if exists {
			log.Printf("[AgentsCreationRequestsCreate] duplicate request blocked agentID=%q", agentID)

			// c.JSON(http.StatusConflict, Response{Status: false, Message: "an active request for this agent is already pending or approved"})
			c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{"requestID": "duplicate"}})

			return
		}
	}

	id := uuid.New().String()
	if err := h.db.CreateRequest(id, "deploy_agent", policy, creatorDID, agentID, agentName, requestInfo, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to create request: %v", err)})
		return
	}

	// Notify all admins in the org.
	log.Printf("[AgentsCreationRequestsCreate] looking up all admins for orgID=%q", orgID)
	adminEmails, adminErr := h.db.GetAllAdminEmailsByOrgID(orgID)
	if adminErr != nil {
		log.Printf("[AgentsCreationRequestsCreate] GetAllAdminEmailsByOrgID failed orgID=%q err=%v", orgID, adminErr)
	} else if len(adminEmails) == 0 {
		log.Printf("[AgentsCreationRequestsCreate] no admin emails found for orgID=%q — check new_admins table has email column populated", orgID)
	} else {
		requesterName, _, _ := h.db.GetOrgUserEmailByDID(creatorDID)
		log.Printf("[AgentsCreationRequestsCreate] found %d admin email(s)=%v requester=%q agentName=%q requestID=%q", len(adminEmails), adminEmails, requesterName, agentName, id)
		for _, adminEmail := range adminEmails {
			if strings.TrimSpace(adminEmail) == "" {
				log.Printf("[AgentsCreationRequestsCreate] skipping admin with empty email")
				continue
			}
			log.Printf("[AgentsCreationRequestsCreate] sending email to admin=%q", adminEmail)
			h.sendMail(email.AgentCreationRequestNew(adminEmail, agentName, requesterName, id))
		}
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
		agentDID := existing.AgentDID
		log.Printf("[AgentCreationRequestSubmit] calling create-agent requestID=%s agentDID=%s agentName=%s adminDID=%s", req.RequestID, existing.AgentDID, existing.AgentName, adminDID)
		callStart := time.Now()
		nftID, err := h.callCreateAgent(existing.AgentName, policy, adminDID, existing.OrgID, agentDID)
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
	if err := h.callUpdateAgent(req.AgentName, nftID, req.Policy, c.GetString(CtxDID), orgID); err != nil {
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

	if err := h.db.RegisterOrgUser(apiKey, req.OrgID, req.Name, req.Email, string(passwordHash)); err != nil {
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

// GET /dashboard/v1/threat-by-id?threat_id=intent-abc-threat-3
func (h *Handler) ThreatByID(c *gin.Context) {
	threatID := c.Query("threat_id")
	if threatID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "threat_id is required"})
		return
	}

	threat, err := h.db.GetThreatByID(threatID)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: fmt.Sprintf("threat %s not found", threatID)})
		return
	}

	codeInfo, _ := h.db.GetThreatCodeDetail(threat.ThreatCode)

	data := gin.H{
		"id":             threat.ID,
		"intent_id":      threat.IntentID,
		"interaction_id": threat.InteractionID,
		"time":           threat.Time.UTC().Format(time.RFC3339),
		"threat_code":    threat.ThreatCode,
		"message":        threat.Message,
	}
	if codeInfo != nil {
		data["title"] = codeInfo.Title
		data["description"] = codeInfo.Description
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

// fetchCbacDecisionReason calls the cbac-decisions service for the given envelope hash
// and returns the "reason" field from the response. Returns empty string on any error.
func (h *Handler) fetchCbacDecisionReason(hash string) string {
	if h.cbacServiceURL == "" || hash == "" {
		return ""
	}
	url := h.cbacServiceURL + "cbac-decisions/by-hash/" + hash
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[cbac] GET %s: %v", url, err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[cbac] GET %s: status %d", url, resp.StatusCode)
		return ""
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Printf("[cbac] decode response for hash=%s: %v", hash, err)
		return ""
	}
	return body.Reason
}

// GET /dashboard/v1/threat-events?page=1&limit=10
func (h *Handler) ThreatEvents(c *gin.Context) {
	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	limit := 10
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		limit = l
	}
	page := 1
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	offset := (page - 1) * limit

	threats, total, err := h.db.GetThreats(orgID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch threats: %v", err)})
		return
	}

	type threatItem struct {
		ID            string `json:"id"`
		IntentID      string `json:"intent_id"`
		InteractionID string `json:"interaction_id"`
		Time          string `json:"time"`
		ThreatCode    int    `json:"threat_code"`
		Message       string `json:"message"`
	}
	items := make([]threatItem, 0, len(threats))
	for _, t := range threats {
		items = append(items, threatItem{
			ID:            t.ID,
			IntentID:      t.IntentID,
			InteractionID: t.InteractionID,
			Time:          t.Time.UTC().Format(time.RFC3339),
			ThreatCode:    t.ThreatCode,
			Message:       t.Message,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"threats": items,
		"total":   total,
		"page":    page,
		"limit":   limit,
	}})
}

// GET /dashboard/v1/top-threats
func (h *Handler) TopThreats(c *gin.Context) {
	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	top, err := h.db.GetTopThreats(orgID, 5)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch top threats: %v", err)})
		return
	}

	type topItem struct {
		ThreatCode int    `json:"threat_code"`
		Title      string `json:"title"`
		Count      int    `json:"count"`
	}
	items := make([]topItem, 0, len(top))
	for _, t := range top {
		items = append(items, topItem{
			ThreatCode: t.ThreatCode,
			Title:      t.Title,
			Count:      t.Count,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: items})
}

// GET /dashboard/v1/threat-detail?threat_code=2001
func (h *Handler) ThreatDetail(c *gin.Context) {
	orgID := c.GetString(CtxOrgID)
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, Response{Status: false, Message: "missing org context"})
		return
	}

	code, err := strconv.Atoi(c.Query("threat_code"))
	if err != nil || code == 0 {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "threat_code is required"})
		return
	}

	codeInfo, err := h.db.GetThreatCodeDetail(code)
	if err != nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: fmt.Sprintf("threat code %d not found", code)})
		return
	}

	threats, total, err := h.db.GetThreatsByCode(orgID, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch threats: %v", err)})
		return
	}

	type threatItem struct {
		ID            string `json:"id"`
		IntentID      string `json:"intent_id"`
		InteractionID string `json:"interaction_id"`
		Time          string `json:"time"`
		Message       string `json:"message"`
	}
	items := make([]threatItem, 0, len(threats))
	for _, t := range threats {
		items = append(items, threatItem{
			ID:            t.ID,
			IntentID:      t.IntentID,
			InteractionID: t.InteractionID,
			Time:          t.Time.UTC().Format(time.RFC3339),
			Message:       t.Message,
		})
	}

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"threat_code": codeInfo.Code,
		"title":       codeInfo.Title,
		"description": codeInfo.Description,
		"count":       total,
		"threats":     items,
	}})
}
