package change

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Plan is the shared description of an intended change. It is produced before
// anything is written and is safe to show, log or hand to another manager: it
// contains hashes and scope only, never config bytes, keys or user identifiers.
//
// The same Plan is emitted by a dry run and by the real apply for the same
// inputs; Fingerprint is what an operator (or an audit log) can compare.
type Plan struct {
	Operation        string   `json:"operation"`
	Resource         string   `json:"resource"`
	OldSHA256        string   `json:"oldSha256"`
	NewSHA256        string   `json:"newSha256,omitempty"`
	Changed          []string `json:"changed,omitempty"`
	AffectedServices []string `json:"affectedServices,omitempty"`
	DisconnectRisk   string   `json:"disconnectRisk"`
	ValidationSteps  []string `json:"validationSteps,omitempty"`
	RollbackScope    string   `json:"rollbackScope"`
	Ownership        string   `json:"ownership"`
	Fingerprint      string   `json:"fingerprint"`
}

// BuildPlan fills in the stable fingerprint. Changed fields are sorted so the
// fingerprint does not depend on map or diff iteration order.
func BuildPlan(p Plan) Plan {
	p.Changed = append([]string(nil), p.Changed...)
	sort.Strings(p.Changed)
	p.AffectedServices = append([]string(nil), p.AffectedServices...)
	sort.Strings(p.AffectedServices)
	p.ValidationSteps = append([]string(nil), p.ValidationSteps...)

	h := sha256.New()
	for _, field := range []string{
		p.Operation, p.Resource, p.OldSHA256, p.NewSHA256,
		strings.Join(p.Changed, ","), p.RollbackScope,
		strings.Join(p.AffectedServices, ","),
	} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	p.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
	return p
}

// MarshalPlan renders the plan as the JSON artifact stored beside a backup.
func MarshalPlan(p Plan) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
