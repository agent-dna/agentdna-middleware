package main

type Response struct {
	Status bool `json:"status"`
	Data   any  `json:"data"`
	// Empty if status is True
	Message string `json:"message"`
}

// txPayload models the deploy-nft request body.
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

