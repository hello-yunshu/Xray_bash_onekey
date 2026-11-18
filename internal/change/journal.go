package change

import (
	"bufio"
	"bytes"
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
	ServicePath   string `json:"servicePath,omitempty"`
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

// Read returns the bounded transaction history. The canonical form is one JSON
// array; a line-delimited file is still accepted so an older or hand-edited
// record does not disappear. A missing file is not an error.
func (j Journal) Read() ([]Entry, error) {
	raw, err := os.ReadFile(j.Path)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if json.Unmarshal(raw, &entries) == nil {
		return entries, nil
	}
	entries = nil
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if json.Unmarshal(line, &entry) == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// Record appends or replaces the entry with the same ID.
func (j Journal) Record(e Entry) error {
	if e.UpdatedAt == "" {
		e.UpdatedAt = now()
	}
	entries, _ := j.Read()
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
