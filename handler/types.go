package handler

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type Response struct {
	Status  bool   `json:"status"`
	Data    any    `json:"data,omitempty"`
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
	Data       string  `json:"data"`
	ParentNFTId string  `json:"parentNFTId,omitempty"`
}

type SmartContractInfo struct {
	SmartContractId string  `json:"smartContractId"`
	Value           float64 `json:"value"`
	Data            string  `json:"data"`
}

// ── Blockchain transaction provenance (POST /rubix/v1/tx, /rubix/v1/signature) ──

// txResponse is the response body of POST /rubix/v1/tx. We extract result.id and
// store it as provenance_req_id; status=false means the tx failed to initiate.
type txResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Result  struct {
		ID string `json:"id"`
	} `json:"result"`
}

// signatureRequest is the request body of POST /rubix/v1/signature. Its id is the
// value returned by the earlier /tx call and links back to the provenance rows.
type signatureRequest struct {
	ID string `json:"id"`
}

// signatureResponse is the response body of POST /rubix/v1/signature. We extract the
// transactionID and the first mintedNFTChildren[].childNFTId.
type signatureResponse struct {
	Status bool   `json:"status"`
	Result struct {
		MintedNFTChildren []struct {
			ChildNFTId string `json:"childNFTId"`
		} `json:"mintedNFTChildren"`
		TransactionID string `json:"transactionID"`
	} `json:"result"`
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

type workflowEnvelope struct {
	From           string              `json:"from_"`
	To             string              `json:"to,omitempty"`
	Payload        json.RawMessage     `json:"payload"`
	Epoch          int64               `json:"epoch"`
	Code           int                 `json:"status_code"`
	RunID          string              `json:"run_id"`
	Hash           string              `json:"hash"`
	Signature      string              `json:"signature"`
	RawData        json.RawMessage     `json:"raw_data,omitempty"`
	ParentEnvelope []*workflowEnvelope `json:"parent_envelope"`
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
	Signature string
	Hash      string
	Epoch     int64
}
