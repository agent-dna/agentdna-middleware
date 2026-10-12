package handler

import (
	"sort"
	"strconv"
	"strings"

	"agentdna-ratelimit-auth/db"
)

// What the evidence for one request adds up to.
//
// With a single observation point only "observed" and "not_observed" occur.
// The other two appear once a run is watched from more than one place.
const (
	EvidenceNotObserved = "not_observed"
	EvidenceObserved    = "observed"
	EvidenceConfirmed   = "confirmed"
	EvidenceMismatch    = "mismatch"
)

// Where a record was taken.
//
// Every observation point but one watches a request arrive: the agent sending
// it, a gateway in front of the destination, the destination receiving it.
// server_out is the odd one - the call the server then made to answer it, with
// a credential that is meant to be different.
const SourceServerOut = "server_out"

// HopEvidence is what was observed about one interaction's authentication.
//
// The top-level fields are the credential this hop arrived with. BackendCalls
// are what the server then presented to its own backends to answer it - often
// a key of its own, which is where a user's identity stops.
type HopEvidence struct {
	Status       string        `json:"status"`
	Sources      []string      `json:"sources,omitempty"`
	AuthMethod   string        `json:"authMethod,omitempty"`
	CredentialID string        `json:"credentialID,omitempty"`
	IdentityID   *string       `json:"identityID,omitempty"`
	AuthStatus   string        `json:"authStatus,omitempty"`
	BackendCalls []BackendCall `json:"backendCalls,omitempty"`
}

// BackendCall is one outbound call a server made while serving a hop.
type BackendCall struct {
	Destination  string  `json:"destination"`
	AuthMethod   string  `json:"authMethod"`
	CredentialID string  `json:"credentialID,omitempty"`
	IdentityID   *string `json:"identityID,omitempty"`
	AuthStatus   string  `json:"authStatus"`
}

// Continuity is what a run's evidence shows as a whole.
//
// Three different events are reported separately, because conflating them
// produces answers we never observed:
//
//	credential changed   often just a token refresh
//	identity changed     a different person or service, seen
//	identity unreadable  an opaque credential - we stopped being able to tell
//
// Worked out on every read rather than stored, so the evidence stays the record
// and a better reading applies to old runs without rewriting anything.
type Continuity struct {
	StartingCredential  string `json:"startingCredential"`
	StartingIdentity    string `json:"startingIdentity"`
	CredentialChangedAt string `json:"credentialChangedAt"`
	IdentityChangedAt   string `json:"identityChangedAt"`
	IdentityUnknownFrom string `json:"identityUnknownFrom"`
	IdentityContinued   bool   `json:"identityContinued"`
	RequestsObserved    int    `json:"requestsObserved"`
	RequestsTotal       int    `json:"requestsTotal"`
}

// hopRef is one interaction and the request it came from. Both are needed: the
// interaction id is what the dashboard shows, the signature is what identifies
// the underlying request.
type hopRef struct {
	InteractionID string
	Signature     string
}

// evidenceForHop collapses every record for one request into a single view.
//
// Only the points that watched this request arrive are compared. server_out is
// the next leg - what the server presented to its own backend - and is meant to
// carry a different credential. Comparing it would report a mismatch on every
// hop that did its job.
func evidenceForHop(records []*db.AuthEvidenceRecord) HopEvidence {
	if len(records) == 0 {
		return HopEvidence{Status: EvidenceNotObserved}
	}

	// The query does not order its rows. Sorting by source, then destination,
	// is what makes the same evidence always read the same way.
	sort.Slice(records, func(a, b int) bool {
		if records[a].Source != records[b].Source {
			return records[a].Source < records[b].Source
		}
		return records[a].Destination < records[b].Destination
	})

	view := HopEvidence{Status: EvidenceObserved}
	onWire := make([]*db.AuthEvidenceRecord, 0, len(records))
	for _, r := range records {
		if len(view.Sources) == 0 || view.Sources[len(view.Sources)-1] != r.Source {
			view.Sources = append(view.Sources, r.Source)
		}
		if r.Source == SourceServerOut {
			view.BackendCalls = append(view.BackendCalls, BackendCall{
				Destination:  r.Destination,
				AuthMethod:   r.AuthMethod,
				CredentialID: r.CredentialID,
				IdentityID:   r.IdentityID,
				AuthStatus:   r.AuthStatus,
			})
		} else {
			onWire = append(onWire, r)
		}
	}

	// Only a point that watched this request arrive can say what it arrived
	// with. With none, the hop's own credential is left empty rather than
	// filled from a backend call - that key is the server's, not the caller's.
	if len(onWire) == 0 {
		return view
	}
	view.AuthMethod = onWire[0].AuthMethod
	view.CredentialID = onWire[0].CredentialID
	view.IdentityID = onWire[0].IdentityID
	view.AuthStatus = onWire[0].AuthStatus

	// One end of the wire: nothing to agree or disagree with.
	if len(onWire) < 2 {
		return view
	}

	// Fingerprints made with different keys are not comparable. A key change,
	// or one misconfigured observation point, must not render as a wall of
	// disagreements that never happened.
	sameKey, sameCredential := true, true
	first := onWire[0]
	for _, r := range onWire[1:] {
		if r.KeyVersion != first.KeyVersion {
			sameKey = false
		}
		if r.CredentialID != first.CredentialID {
			sameCredential = false
		}
	}

	switch {
	case !sameKey:
		view.Status = EvidenceObserved
	case sameCredential:
		view.Status = EvidenceConfirmed
	default:
		view.Status = EvidenceMismatch
	}
	return view
}

// analyseContinuity walks a run and reports what changed and where.
//
// One request can produce several interactions when it fans out to concurrent
// children, so the walk skips signatures already seen. Counting rows instead
// would report more requests than were made.
func analyseContinuity(order []hopRef, evidence map[string]HopEvidence) Continuity {
	result := Continuity{}
	started := false
	seen := map[string]bool{}

	for _, ref := range order {
		if seen[ref.Signature] {
			continue
		}
		seen[ref.Signature] = true
		result.RequestsTotal++

		hop := evidence[ref.InteractionID]
		if hop.Status == EvidenceNotObserved || hop.AuthMethod == "" || hop.AuthMethod == "none" {
			continue
		}
		result.RequestsObserved++

		if !started {
			// The run's first credential-bearing request. Nothing else has had
			// a chance to introduce a credential yet, so this is what the run
			// started as.
			result.StartingCredential = hop.CredentialID
			if hop.IdentityID != nil {
				result.StartingIdentity = *hop.IdentityID
			}
			result.IdentityContinued = hop.IdentityID != nil
			started = true
			continue
		}

		if result.CredentialChangedAt == "" && hop.CredentialID != result.StartingCredential {
			result.CredentialChangedAt = ref.InteractionID
		}

		// NULL is not a change. An opaque credential may well be the same
		// identity - we simply stopped being able to tell. Reporting it as a
		// change would claim something never observed.
		if hop.IdentityID == nil {
			if result.IdentityUnknownFrom == "" {
				result.IdentityUnknownFrom = ref.InteractionID
			}
			result.IdentityContinued = false
			continue
		}

		if result.StartingIdentity != "" && *hop.IdentityID != result.StartingIdentity {
			if result.IdentityChangedAt == "" {
				result.IdentityChangedAt = ref.InteractionID
			}
			result.IdentityContinued = false
		}
	}

	return result
}

// interactionOrder returns a run's hops in the order the chain walk created
// them. Interactions are named "<intentID>-<n>", so the numeric suffix is that
// order - sorting the ids as text would give 1, 10, 11, 2.
//
// This reuses the middleware's own ordering rather than deriving another one.
// If the two ever disagreed, nobody could tell which was right.
func interactionOrder(interactions []*db.InteractionRecord) []hopRef {
	refs := make([]hopRef, 0, len(interactions))
	for _, i := range interactions {
		refs = append(refs, hopRef{InteractionID: i.InteractionID, Signature: i.Signature})
	}
	sort.SliceStable(refs, func(a, b int) bool {
		return suffixIndex(refs[a].InteractionID) < suffixIndex(refs[b].InteractionID)
	})
	return refs
}

func suffixIndex(interactionID string) int {
	idx := strings.LastIndex(interactionID, "-")
	if idx < 0 {
		return 0
	}
	n, err := strconv.Atoi(interactionID[idx+1:])
	if err != nil {
		return 0
	}
	return n
}

// authEvidenceForIntent returns the per-interaction evidence and what the run
// shows as a whole.
//
// On any error it returns empty results rather than failing the request:
// missing evidence must read as "not observed", never as a broken page.
func (h *Handler) authEvidenceForIntent(
	intentID string,
	interactions []*db.InteractionRecord,
) (map[string]HopEvidence, Continuity) {
	byRequest, err := h.db.GetAuthEvidenceByIntent(intentID)
	if err != nil {
		byRequest = map[string][]*db.AuthEvidenceRecord{}
	}

	perHop := make(map[string]HopEvidence, len(interactions))
	for _, i := range interactions {
		perHop[i.InteractionID] = evidenceForHop(byRequest[i.Signature])
	}

	return perHop, analyseContinuity(interactionOrder(interactions), perHop)
}
