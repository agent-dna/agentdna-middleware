package handler

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"agentdna-ratelimit-auth/db"
)

// threatCodesJSON is handler/error_code.json, compiled into the binary so the
// codes are available wherever the server runs from.
//
//go:embed error_code.json
var threatCodesJSON []byte

// loadThreatCodes parses error_code.json. Every entry with a "code" is a
// tracked threat code, returned in file order for SyncThreatCodes. Exactly
// one entry must have no "code": it describes the Unknown bucket, used for
// threats whose code is not tracked, and is returned separately.
func loadThreatCodes() ([]db.ThreatCodeRecord, db.ThreatCodeRecord, error) {
	var entries []struct {
		Code        *int   `json:"code"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(threatCodesJSON, &entries); err != nil {
		return nil, db.ThreatCodeRecord{}, fmt.Errorf("parse error_code.json: %w", err)
	}

	var (
		codes      []db.ThreatCodeRecord
		unknown    db.ThreatCodeRecord
		seen       = map[int]bool{}
		unknownSet bool
	)
	for i, e := range entries {
		rec := db.ThreatCodeRecord{Title: e.Title, Severity: e.Severity, Description: e.Description}
		if e.Code == nil {
			if unknownSet {
				return nil, db.ThreatCodeRecord{}, fmt.Errorf("error_code.json entry %d: second entry without a code", i)
			}
			rec.Code = db.UnknownThreatCode
			unknown, unknownSet = rec, true
			continue
		}
		if *e.Code == db.UnknownThreatCode || *e.Code == 0 {
			return nil, db.ThreatCodeRecord{}, fmt.Errorf("error_code.json entry %d: code %d is reserved for the Unknown bucket", i, *e.Code)
		}
		if seen[*e.Code] {
			return nil, db.ThreatCodeRecord{}, fmt.Errorf("error_code.json entry %d: duplicate code %d", i, *e.Code)
		}
		seen[*e.Code] = true
		rec.Code = *e.Code
		codes = append(codes, rec)
	}
	if !unknownSet {
		return nil, db.ThreatCodeRecord{}, fmt.Errorf("error_code.json: no entry without a code (the Unknown bucket)")
	}
	return codes, unknown, nil
}
