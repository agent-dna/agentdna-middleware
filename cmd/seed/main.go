package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"agentdna-ratelimit-auth/db"

	"github.com/google/uuid"
	cid "github.com/ipfs/go-cid"
	_ "github.com/lib/pq"
	mh "github.com/multiformats/go-multihash"
)

// ── Config ────────────────────────────────────────────────────────────────────

const (
	orgID       = "TEST_ORG_1"
	numIntents  = 24
	minTxns     = 4
	maxTxns     = 13
	threatRatio = 0.35 // ~35% of intents will have threats
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func makeDID(name string) string {
	digest := sha256.Sum256([]byte(name))
	multi, _ := mh.Encode(digest[:], mh.SHA2_256)
	return cid.NewCidV0(multi).String()
}

var (
	agentNames = []string{
		"CoordinatorAgent", "ResearchAgent", "FinanceAgent", "ComplianceAgent",
		"DataAgent", "SummaryAgent", "AuditAgent", "NotifyAgent",
		"RouterAgent", "ValidatorAgent", "PlannerAgent", "ExecutorAgent",
	}

	toolNames = []string{
		"web_search", "database_query", "send_email", "file_reader",
		"api_caller", "pdf_parser", "code_executor", "slack_notifier",
	}

	flowTypes = []string{"simple", "delegated", "cbac", "delegated_cbac", "fan_out", "external_trigger"}

	interactionTypes = []string{"delegate", "execute", "trigger", "response"}
)

func randAgent() (did, name string) {
	n := agentNames[rand.Intn(len(agentNames))]
	return makeDID(n), n
}

func randTool() (did, name string) {
	n := toolNames[rand.Intn(len(toolNames))]
	return makeDID(n), n
}

// buildChain returns a sequence of (fromDID, fromName, toDID, toName, txnType, isThreat)
// representing numTxns hops for one intent. hasThreat controls whether any hop gets flagged.
func buildChain(numTxns int, hasThreat bool) [][6]string {
	// pick 2-4 agents for this intent to form a realistic chain
	numAgents := 2 + rand.Intn(3)
	agents := make([][2]string, numAgents)
	used := map[string]bool{}
	for i := 0; i < numAgents; i++ {
		for {
			d, n := randAgent()
			if !used[d] {
				agents[i] = [2]string{d, n}
				used[d] = true
				break
			}
		}
	}

	// threat goes on a random hop if enabled
	threatHop := -1
	if hasThreat {
		threatHop = rand.Intn(numTxns)
	}

	hops := make([][6]string, numTxns)
	for i := 0; i < numTxns; i++ {
		fromAgent := agents[i%numAgents]
		toAgent := agents[(i+1)%numAgents]

		txnType := interactionTypes[rand.Intn(len(interactionTypes))]

		// ~20% chance of a tool_call hop
		isTool := rand.Float32() < 0.2
		toD, toN := toAgent[0], toAgent[1]
		if isTool {
			txnType = "tool_call"
			toD, toN = randTool()
		}

		threat := "false"
		if i == threatHop {
			threat = "true"
		}
		hops[i] = [6]string{fromAgent[0], fromAgent[1], toD, toN, txnType, threat}
	}
	return hops
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL not set")
	}

	database := db.New(dsn)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	_ = rng

	// Fixed initiator user and deployer
	initiatorDID := makeDID("seed_user_1")
	initiatorNFT := makeDID("seed_user_1_nft")

	// Ensure initiator user exists
	if err := database.StoreOrgUser(initiatorNFT, initiatorDID, orgID, "SeedUser", "seed@agentdna.io", "$2a$10$placeholder"); err != nil {
		log.Printf("StoreOrgUser: %v (may already exist)", err)
	}

	// Pre-register all agents and tools
	for _, n := range agentNames {
		d := makeDID(n)
		nft := makeDID(n + "_nft")
		if err := database.StoreNewAgent(nft, d, initiatorDID, orgID, "", n); err != nil {
			log.Printf("StoreNewAgent %s: %v", n, err)
		}
	}
	for _, n := range toolNames {
		d := makeDID(n)
		if err := database.StoreNewTool(d, n, orgID); err != nil {
			log.Printf("StoreNewTool %s: %v", n, err)
		}
	}

	threatCount := 0

	for i := 0; i < numIntents; i++ {
		intentID := uuid.New().String()
		numTxns := minTxns + rand.Intn(maxTxns-minTxns+1)
		hasThreat := rand.Float32() < threatRatio
		if hasThreat {
			threatCount++
		}

		hops := buildChain(numTxns, hasThreat)

		interactionIDs := make([]string, 0, len(hops))
		anyThreat := false

		for j, hop := range hops {
			iid := fmt.Sprintf("%s-%d", intentID, j+1)
			interactionIDs = append(interactionIDs, iid)
			threat := hop[5] == "true"
			if threat {
				anyThreat = true
			}
			dir := "outbound"
			if j%2 == 1 {
				dir = "inbound"
			}
			if err := database.StoreNewInteraction(
				iid, hop[0], hop[1], hop[2], hop[3], hop[4], dir, threat, intentID, orgID, "", time.Time{},
			); err != nil {
				log.Printf("StoreNewInteraction intent=%s hop=%d: %v", intentID, j, err)
			}
			if hop[4] == "tool_call" {
				_ = database.StoreNewTool(hop[2], hop[3], orgID)
			}
		}

		flowType := flowTypes[rand.Intn(len(flowTypes))]
		chainDepth := len(hops)

		if err := database.StoreIntent(intentID, initiatorDID, orgID, flowType, "seed_user_1", chainDepth, anyThreat, interactionIDs); err != nil {
			log.Printf("StoreIntent %s: %v", intentID, err)
		}

		log.Printf("[seed] intent %2d/%d id=%s txns=%2d threat=%v flowType=%s",
			i+1, numIntents, intentID, numTxns, anyThreat, flowType)
	}

	log.Printf("[seed] done — %d intents seeded (%d with threats, %d clean)", numIntents, threatCount, numIntents-threatCount)
}
