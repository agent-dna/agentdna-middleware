package handler

import "github.com/golang-jwt/jwt/v5"

type Response struct {
	Status  bool   `json:"status"`
	Data    any    `json:"data"`
	Message string `json:"message"`
}

type txPayload struct {
	Initiator string                  `json:"initiator"`
	Owner     string                  `json:"owner"`
	Tokens    transactionTokenDetails `json:"tokens"`
	Memo      string                  `json:"memo"`
}

type transactionTokenDetails struct {
	RBT                  float64             `json:"rbt"`
	FT                   []FTInfo            `json:"ft"`
	NFT                  []NFTInfo           `json:"nft"`
	SmartContract        []SmartContractInfo `json:"smartContract"`
	TransferNFTOwnership bool                `json:"transferNftOwnership"`
}

type FTInfo struct {
	FTName      string  `json:"ftName"`
	NumberOfFts float64 `json:"numberOfFts"`
	CreatorDID  string  `json:"creatorDID"`
}

type NFTInfo struct {
	NFTId string  `json:"nftId"`
	Value float64 `json:"value"`
	Data  string  `json:"data"`
}

type SmartContractInfo struct {
	SmartContractId string  `json:"smartContractId"`
	Value           float64 `json:"value"`
	Data            string  `json:"data"`
}

type JWTClaims struct {
	DID    string `json:"did"`
	Email  string `json:"email"`
	OrgID  string `json:"org_id"`
	NFTID  string `json:"nft_id"`
	APIKey string `json:"api_key"`
	jwt.RegisteredClaims
}

const (
	NFTTypeUser   = "user_nft"
	NFTTypeAgent  = "agent_nft"
	NFTTypeIntent = "intent_workflow"
)

type userNFTData struct {
	Type     string          `json:"type"`
	UserDID  string          `json:"user_did"`
	Metadata userNFTMetadata `json:"metadata"`
}

type userNFTMetadata struct {
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	OrgID           string   `json:"orgId"`
	AgentAccessList []string `json:"agentAccessList"`
}

type agentNFTData struct {
	Type          string           `json:"type"`
	AgentDID      string           `json:"agent_did"`
	AgentMetadata agentNFTMetadata `json:"agent_metadata"`
	Policy        string           `json:"policy"`
}

type agentNFTMetadata struct {
	OrgID     string `json:"orgId"`
	Deployer  string `json:"deployer"`
	AgentName string `json:"agent_name"`
}

// intentWorkflowData is the top-level structure for the intent_workflow format.
type intentWorkflowData struct {
	Type     string            `json:"type"`
	Version  string            `json:"version"`
	Remarks  string            `json:"remarks"`
	Info     map[string]any    `json:"info"`
	Envelope *workflowEnvelope `json:"envelope"`
}

type workflowActor struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Type     string         `json:"type"` // "human", "agent", "app"
	Metadata map[string]any `json:"metadata"`
}

type workflowIssue struct {
	Depth  int    `json:"depth"`
	Reason string `json:"reason"`
}

type workflowEnvelope struct {
	From           workflowActor     `json:"from_"`
	To             workflowActor     `json:"to"`
	Payload        string            `json:"payload"`
	Epoch          int64             `json:"epoch"`
	Metadata       map[string]any    `json:"metadata"`
	Signature      string            `json:"signature"`
	Issues         []workflowIssue   `json:"issues"`
	ParentEnvelope *workflowEnvelope `json:"parent_envelope"`
}

// chainNFTData is the top-level structure of an intent NFT using the chain spec.
type chainNFTData struct {
	Type         string            `json:"type"`
	Comment      string            `json:"comment"`
	Executor     string            `json:"executor"`
	DID          string            `json:"did"`
	Verification chainVerification `json:"verification"`
	Chain        *chainBlock       `json:"chain"`
}

type chainVerification struct {
	Status      string   `json:"status"`
	ChainDepth  int      `json:"chain_depth"`
	TrustIssues []string `json:"trust_issues"`
}

type chainBlock struct {
	Agent        string               `json:"agent"`
	Name         string               `json:"name"`
	Direction    string               `json:"direction"`
	Type         string               `json:"type"`
	Envelope     chainEnvelope        `json:"envelope"`
	Signature    string               `json:"signature"`
	Verification chainBlockVerification `json:"verification"`
}

type chainEnvelope struct {
	Payload     map[string]any `json:"payload"`
	ParentBlock *chainBlock    `json:"parent_block,omitempty"`
}

type chainBlockVerification struct {
	SignatureValid bool     `json:"signature_valid"`
	TrustIssues   []string `json:"trust_issues"`
}

// interactionExtract holds one extracted hop from the chain.
type interactionExtract struct {
	FromDID   string
	FromName  string
	ToDID     string
	ToName    string
	Type      string
	Direction string
	Threat    bool
	Message   string
}
