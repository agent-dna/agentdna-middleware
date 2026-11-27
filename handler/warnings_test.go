package handler

import (
	"database/sql"
	"reflect"
	"testing"
	"time"

	"agentdna-ratelimit-auth/db"
)

func TestComputeWarnings(t *testing.T) {
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	firstUse := func(daysAgo int) sql.NullTime {
		return sql.NullTime{Time: now.AddDate(0, 0, -daysAgo), Valid: true}
	}
	maxAge := 90 * 24 * time.Hour

	cases := []struct {
		name  string
		facts []db.WarningFact
		want  []int64
	}{
		{"no evidence", []db.WarningFact{{Time: now}}, []int64{}},
		{"trusted destination, clean credential", []db.WarningFact{{
			Time: now, Destination: "GET https://a.com", TrustStatus: "Trusted",
			CredentialID: "c1", CredentialStatus: "active", CredentialResourceCount: 1, CredentialFirstUse: firstUse(1),
		}}, []int64{}},
		{"unreviewed destination", []db.WarningFact{{Time: now, Destination: "GET https://a.com", TrustStatus: "Unreviewed"}}, []int64{5101}},
		{"flagged destination", []db.WarningFact{{Time: now, Destination: "GET https://a.com", TrustStatus: "Flagged"}}, []int64{5101}},
		{"no destination ignores trust status", []db.WarningFact{{Time: now, TrustStatus: "Unreviewed"}}, []int64{}},
		// 5105 is disabled for now: a key on several resources gives no warning.
		{"credential on two resources", []db.WarningFact{{Time: now, CredentialID: "c1", CredentialResourceCount: 2}}, []int64{}},
		{"compromised credential", []db.WarningFact{{Time: now, CredentialID: "c1", CredentialStatus: "compromised", CredentialResourceCount: 1}}, []int64{5107}},
		{"flagged credential", []db.WarningFact{{Time: now, CredentialID: "c1", CredentialStatus: "flagged", CredentialResourceCount: 1}}, []int64{5107}},
		{"old credential", []db.WarningFact{{Time: now, CredentialID: "c1", CredentialStatus: "active", CredentialFirstUse: firstUse(91)}}, []int64{5108}},
		{"credential exactly at max age", []db.WarningFact{{Time: now, CredentialID: "c1", CredentialStatus: "active", CredentialFirstUse: firstUse(90)}}, []int64{}},
		{"several rules across rows, deduped and sorted", []db.WarningFact{
			{Time: now, Destination: "GET https://a.com", TrustStatus: "Trusted", CredentialID: "c1", CredentialStatus: "flagged", CredentialResourceCount: 3},
			{Time: now, Destination: "GET https://b.com", TrustStatus: "Unreviewed", CredentialID: "c1", CredentialStatus: "flagged", CredentialResourceCount: 3},
		}, []int64{5101, 5107}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeWarnings(tc.facts, maxAge); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ComputeWarnings = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("max age 0 turns 5108 off", func(t *testing.T) {
		f := []db.WarningFact{{Time: now, CredentialID: "c1", CredentialStatus: "active", CredentialFirstUse: firstUse(1000)}}
		if got := ComputeWarnings(f, 0); len(got) != 0 {
			t.Errorf("ComputeWarnings = %v, want none", got)
		}
	})
}

func TestParseCredentialMaxAge(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"":      0,
		"90d":   90 * 24 * time.Hour,
		"2160h": 2160 * time.Hour,
	} {
		if got, err := ParseCredentialMaxAge(raw); err != nil || got != want {
			t.Errorf("ParseCredentialMaxAge(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"abc", "-1d", "xd", "-5h"} {
		if _, err := ParseCredentialMaxAge(raw); err == nil {
			t.Errorf("ParseCredentialMaxAge(%q): want error", raw)
		}
	}
}

func TestIsTxnThreatCode(t *testing.T) {
	for code, want := range map[int]bool{0: false, 1000: false, 1001: true, 3303: true, 5100: false, 5101: false, 5199: false, 5200: true, 9104: true} {
		if got := isTxnThreatCode(code); got != want {
			t.Errorf("isTxnThreatCode(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestParseCredentialRejectionLimit(t *testing.T) {
	for raw, want := range map[string]int{"": 0, "0": 0, "5": 5, " 12 ": 12} {
		if got, err := ParseCredentialRejectionLimit(raw); err != nil || got != want {
			t.Errorf("ParseCredentialRejectionLimit(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"abc", "-1", "2.5", "5x"} {
		if _, err := ParseCredentialRejectionLimit(raw); err == nil {
			t.Errorf("ParseCredentialRejectionLimit(%q): want error", raw)
		}
	}
}
