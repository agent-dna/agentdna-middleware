package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Env is one signed envelope of an intent_workflow DAG, built the way an
// agent runtime would mint it. It marshals to the exact wire shape the
// middleware parses (handler.workflowEnvelope).
type Env struct {
	From    string
	Payload any // string, []map[string]any content blocks, object, or nil
	Epoch   int64
	Code    int
	RunID   string
	Hash    string
	Sig     string
	Parents []*Env
}

func (e *Env) MarshalJSON() ([]byte, error) {
	parents := e.Parents
	if parents == nil {
		parents = []*Env{}
	}
	return json.Marshal(struct {
		From      string `json:"from"`
		Payload   any    `json:"payload"`
		Epoch     int64  `json:"epoch"`
		Code      int    `json:"status_code"`
		RunID     string `json:"run_id"`
		Hash      string `json:"hash"`
		Signature string `json:"signature"`
		Parents   []*Env `json:"parent_envelope"`
	}{e.From, e.Payload, e.Epoch, e.Code, e.RunID, e.Hash, e.Sig, parents})
}

// Text is the message the middleware should extract from this envelope's
// payload (mirrors handler.extractPayloadText for the shapes used here).
func (e *Env) Text() string {
	switch p := e.Payload.(type) {
	case nil:
		return ""
	case string:
		return p
	case []map[string]any:
		for _, b := range p {
			if b["type"] == "text" {
				if s, _ := b["text"].(string); s != "" {
					return s
				}
			}
		}
	}
	raw, _ := json.Marshal(e.Payload)
	return string(raw)
}

// Builder mints envelopes with unique, deterministic hashes/signatures and
// strictly increasing epochs (unless overridden).
type Builder struct {
	key   string
	n     int
	epoch int64
}

func NewBuilder(key string) *Builder {
	return &Builder{key: key, epoch: time.Now().Unix() - 3600}
}

type Opt func(*Env)

func Code(c int) Opt       { return func(e *Env) { e.Code = c } }
func Payload(p any) Opt    { return func(e *Env) { e.Payload = p } }
func AtEpoch(ts int64) Opt { return func(e *Env) { e.Epoch = ts } }
func Unsigned() Opt        { return func(e *Env) { e.Sig, e.Hash = "", "" } }

func (b *Builder) make(from string, parents []*Env, opts []Opt) *Env {
	b.n++
	b.epoch++
	e := &Env{
		From:    from,
		Payload: fmt.Sprintf("message %d from %s", b.n, shortDID(from)),
		Epoch:   b.epoch,
		RunID:   b.key,
		Hash:    fmt.Sprintf("%s-h%d", b.key, b.n),
		Sig:     fmt.Sprintf("%s-s%d", b.key, b.n),
		Parents: parents,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Root starts a chain: the base envelope with no parent (its From is the
// intent's initiator).
func (b *Builder) Root(from string, opts ...Opt) *Env { return b.make(from, nil, opts) }

// Next is the envelope `from` signs on top of parent.
func (b *Builder) Next(parent *Env, from string, opts ...Opt) *Env {
	return b.make(from, []*Env{parent}, opts)
}

// Join is a fan-in envelope with several parents (parallel branches merging).
func (b *Builder) Join(parents []*Env, from string, opts ...Opt) *Env {
	return b.make(from, parents, opts)
}

// Chain builds a linear chain actors[0] → actors[1] → … and returns the
// newest envelope.
func (b *Builder) Chain(actors ...string) *Env {
	var e *Env
	for i, a := range actors {
		if i == 0 {
			e = b.Root(a)
		} else {
			e = b.Next(e, a)
		}
	}
	return e
}

// IntentNFTData is the tokens.nft[].data string for an intent_workflow NFT.
// An empty id omits the field entirely.
func IntentNFTData(id string, root *Env) string {
	m := map[string]any{
		"type":     "intent_workflow",
		"version":  "1",
		"remarks":  "txnsim",
		"info":     map[string]any{"source": "txnsim"},
		"envelope": root,
	}
	if id != "" {
		m["id"] = id
	}
	return mustJSON(m)
}

// AgentNFTData is the tokens.nft[].data string for an agent_nft.
func AgentNFTData(agentDID, name, deployer, orgID, policy string) string {
	return mustJSON(map[string]any{
		"type":      "agent_nft",
		"agent_did": agentDID,
		"policy":    policy,
		"agent_metadata": map[string]any{
			"orgId":      orgID,
			"deployer":   deployer,
			"agent_name": name,
		},
	})
}

// NFT is one tokens.nft[] entry.
type NFT struct {
	ID       string
	ParentID string
	Data     string
}

// TxBody is the POST /rubix/v1/tx body an agent runtime submits.
func TxBody(executor string, nfts ...NFT) []byte {
	list := make([]map[string]any, 0, len(nfts))
	for _, n := range nfts {
		entry := map[string]any{"nftId": n.ID, "value": 1, "data": n.Data}
		if n.ParentID != "" {
			entry["parentNFTId"] = n.ParentID
		}
		list = append(list, entry)
	}
	return []byte(mustJSON(map[string]any{
		"initiator": executor,
		"owner":     executor,
		"memo":      "txnsim",
		"tokens": map[string]any{
			"rbt":                  0,
			"ft":                   []any{},
			"nft":                  list,
			"smartContract":        []any{},
			"transferNftOwnership": false,
		},
	}))
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func shortDID(did string) string {
	if i := strings.LastIndex(did, ":"); i >= 0 {
		return did[i+1:]
	}
	return did
}
