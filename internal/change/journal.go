package change

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Journal states are bounded and never contain config bytes or secrets.
const (
	StatePrepared         = "PREPARED"
	StateRejected         = "REJECTED"
	StateConflict         = "CONFLICT"
	StateFailed           = "FAILED"
	StateRolledBack       = "ROLLED_BACK"
	StateCommitted        = "COMMITTED"
	StateRecoveryRequired = "RECOVERY_REQUIRED"
)

// Entry is one transaction record.
type Entry struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	Target        string `json:"target"`
	OldSHA256     string `json:"oldSha256"`
	NewSHA256     string `json:"newSha256,omitempty"`
	ValidatorExit int    `json:"validatorExit,omitempty"`
	ServiceExit   int    `json:"serviceExit,omitempty"`
	Reason        string `json:"reason,omitempty"`
	StartedAt     string `json:"startedAt"`
	UpdatedAt     string `json:"updatedAt"`
}

const maxEntries = 20

// Journal persists a bounded transaction history atomically.
type Journal struct {
	Path string
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Record appends or replaces the entry with the same ID.
func (j Journal) Record(e Entry) error {
	if e.UpdatedAt == "" {
		e.UpdatedAt = now()
	}
	var entries []Entry
	if b, err := os.ReadFile(j.Path); err == nil {
		_ = json.Unmarshal(b, &entries)
	}
	replaced := false
	for i := range entries {
		if entries[i].ID == e.ID {
			entries[i] = e
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, e)
	}
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(j.Path), 0755); err != nil {
		return err
	}
	return writeAtomic(j.Path, b, 0600, os.Getuid(), os.Getgid())
}
