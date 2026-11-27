package handler

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentdna-ratelimit-auth/db"

	"github.com/gin-gonic/gin"
)

// Warning codes (51xx) are computed by the middleware from auth evidence,
// destination trust status and credential status. They are never read from
// a transaction envelope; see isTxnThreatCode.
const (
	warnUntrustedDestination = 5101 // destination is Unreviewed or Flagged
	warnTokenRejected        = 5102 // token_activity: not implemented yet
	warnIdentitySwitched     = 5103 // token_activity: not implemented yet
	warnWeakAuth             = 5104 // token_activity: not implemented yet
	warnSharedKey            = 5105 // credential sent to more than one resource: DISABLED for now, see ComputeWarnings
	warnPersonalToken        = 5106 // not implemented yet
	warnBadCredential        = 5107 // credential is flagged or compromised
	warnKeyNeverRotated      = 5108 // credential older than DURATION_CREDENTIAL

	warningCodeMin = 5100
	warningCodeMax = 5199
)

// isTxnThreatCode reports whether an envelope's code marks a threat. 0 and
// 1000 are success; 51xx are warnings the middleware computes itself, so an
// envelope carrying one is ignored rather than recorded twice.
func isTxnThreatCode(code int) bool {
	if code == 0 || code == 1000 {
		return false
	}
	return code < warningCodeMin || code > warningCodeMax
}

// ComputeWarnings returns the sorted warning codes for one interaction, given
// its facts (one per auth evidence row). Each rule is checked on its own: an
// interaction can carry several codes. maxAge 0 turns 5108 off.
func ComputeWarnings(facts []db.WarningFact, maxAge time.Duration) []int64 {
	set := map[int64]bool{}
	for _, f := range facts {
		if f.Destination != "" && (f.TrustStatus == "Unreviewed" || f.TrustStatus == "Flagged") {
			set[warnUntrustedDestination] = true
		}
		// 5102 / 5103 / 5104: from token_activity in auth evidence, later.
		// 5106: no logic yet.
		if f.CredentialID == "" {
			continue
		}
		// 5105 is disabled for now: not tracked, so never set and never
		// counted in an intent's warnings. db.New also strips any 5105
		// stored before. To turn it back on, restore this rule and drop that
		// cleanup in db.New.
		//
		// if f.CredentialResourceCount > 1 {
		// 	set[warnSharedKey] = true
		// }
		if f.CredentialStatus == "flagged" || f.CredentialStatus == "compromised" {
			set[warnBadCredential] = true
		}
		if maxAge > 0 && f.CredentialFirstUse.Valid && f.Time.Sub(f.CredentialFirstUse.Time) > maxAge {
			set[warnKeyNeverRotated] = true
		}
	}
	codes := make([]int64, 0, len(set))
	for c := range set {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	return codes
}

// recomputeWarnings rebuilds warning_codes for the interactions in scope (see
// db.RecomputeWarnings). Call it only after the triggering write has
// committed. A failure is logged, not returned: the triggering write already
// succeeded, and the next recompute touching these interactions fixes it.
func (h *Handler) recomputeWarnings(signatures []string, resourceID, credentialID string) {
	maxAge := h.credentialMaxAge
	n, err := h.db.RecomputeWarnings(signatures, resourceID, credentialID, func(facts []db.WarningFact) []int64 {
		return ComputeWarnings(facts, maxAge)
	})
	if err != nil {
		log.Printf("[warnings] recompute signatures=%d resource=%q credential=%q FAILED: %v", len(signatures), resourceID, credentialID, err)
		return
	}
	if n > 0 {
		log.Printf("[warnings] recompute signatures=%d resource=%q credential=%q: %d interaction(s) changed", len(signatures), resourceID, credentialID, n)
	}
}

// ParseCredentialMaxAge reads DURATION_CREDENTIAL: a number of days ("90d")
// or a Go duration ("2160h"). Unset means 0, which turns 5108 off.
func ParseCredentialMaxAge(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(raw, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("DURATION_CREDENTIAL %q: want days like 90d or a duration like 2160h", raw)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("DURATION_CREDENTIAL %q: want days like 90d or a duration like 2160h", raw)
	}
	return d, nil
}

func credentialMaxAgeFromEnv() time.Duration {
	d, err := ParseCredentialMaxAge(os.Getenv("DURATION_CREDENTIAL"))
	if err != nil {
		log.Fatalf("[warnings] %v", err)
	}
	if d == 0 {
		log.Printf("[warnings] DURATION_CREDENTIAL unset, warning 5108 is off")
	}
	return d
}

// warningInfo is code's title and severity from error_code.json.
func (h *Handler) warningInfo(code int64) db.ThreatCodeRecord {
	if rec, ok := h.threatCodes[int(code)]; ok {
		return rec
	}
	return h.unknownThreat
}

// warningsJSON renders an interaction's warning codes with their titles and
// severities from error_code.json.
func (h *Handler) warningsJSON(codes []int64) []gin.H {
	out := make([]gin.H, 0, len(codes))
	for _, c := range codes {
		rec := h.warningInfo(c)
		out = append(out, gin.H{"code": c, "title": rec.Title, "severity": rec.Severity})
	}
	return out
}

// warningCountsJSON renders warning counts as [{code, title, severity,
// count}], count being how many interactions carry the code.
func (h *Handler) warningCountsJSON(counts []db.WarningCount) []gin.H {
	out := make([]gin.H, 0, len(counts))
	for _, w := range counts {
		rec := h.warningInfo(w.Code)
		out = append(out, gin.H{"code": w.Code, "title": rec.Title, "severity": rec.Severity, "count": w.Count})
	}
	return out
}

// intentWarnings returns each intent's warnings in warningCountsJSON's shape,
// with an empty list for intents that have none. A lookup failure is logged
// and gives empty lists, so a list page still renders.
func (h *Handler) intentWarnings(intentIDs []string) map[string][]gin.H {
	out := make(map[string][]gin.H, len(intentIDs))
	counts, err := h.db.GetWarningCountsByIntent(intentIDs)
	if err != nil {
		log.Printf("[warnings] counts for %d intent(s) FAILED: %v", len(intentIDs), err)
	}
	for _, id := range intentIDs {
		out[id] = h.warningCountsJSON(counts[id])
	}
	return out
}
