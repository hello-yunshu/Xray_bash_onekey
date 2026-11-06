package legacybridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Bridge states follow the Phase 03 contract. The sequence is
// DISCOVERED -> PREPARED -> VALIDATED -> ACTIVATING -> COMMITTED.
// Any interruption after ACTIVATING either rolls back (ROLLED_BACK), asks for
// a retry (ROLLBACK_REQUIRED) or stops with an honest RECOVERY_REQUIRED.
const (
	StateDiscovered       = "DISCOVERED"
	StatePrepared         = "PREPARED"
	StateValidated        = "VALIDATED"
	StateActivating       = "ACTIVATING"
	StateCommitted        = "COMMITTED"
	StateRollbackRequired = "ROLLBACK_REQUIRED"
	StateRolledBack       = "ROLLED_BACK"
	StateRecoveryRequired = "RECOVERY_REQUIRED"

	// JournalSchema is the only schema this binary writes or accepts.
	JournalSchema = 1

	journalRel  = "var/lib/idleleo/bridge/journal.json"
	snapshotRel = "var/lib/idleleo/bridge/snapshot"
	planRel     = "var/lib/idleleo/bridge/plan.json"
)

// Step is one recorded bridge action.
type Step struct {
	Name   string `json:"name"`
	At     string `json:"at"`
	Detail string `json:"detail,omitempty"`
}

// Journal is the bridge transaction record. It never stores UUIDs, private
// keys, shortIds or certificate contents.
type Journal struct {
	SchemaVersion   int      `json:"schemaVersion"`
	State           string   `json:"state"`
	Root            string   `json:"root"`
	CreatedAt       string   `json:"createdAt"`
	UpdatedAt       string   `json:"updatedAt"`
	CandidateSHA256 string   `json:"candidateSha256,omitempty"`
	RecoverySHA256  string   `json:"recoverySha256,omitempty"`
	EntryLink       string   `json:"entryLink,omitempty"`
	PlanSHA256      string   `json:"planSha256,omitempty"`
	RuntimeSHA256   string   `json:"runtimeSha256,omitempty"`
	RemovedCron     int      `json:"removedCronLines,omitempty"`
	DeferredTasks   []string `json:"deferredTasks,omitempty"`
	ScheduledJobs   []string `json:"scheduledJobs,omitempty"`
	DegradedJobs    []string `json:"degradedJobs,omitempty"`
	Steps           []Step   `json:"steps"`
	LastError       string   `json:"lastError,omitempty"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// journalPath resolves the journal under the bridge root.
func journalPath(root string) (string, error) {
	p, err := resolve(root, journalRel)
	if err != nil {
		return "", err
	}
	return p, nil
}

func snapshotPath(root string, name string) (string, error) {
	p, err := resolve(root, filepath.Join(snapshotRel, name))
	if err != nil {
		return "", err
	}
	return p, nil
}

// readJournal returns a clear error when the file is absent or unreadable.
func readJournal(root string) (Journal, error) {
	p, err := journalPath(root)
	if err != nil {
		return Journal{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Journal{}, fmt.Errorf("no bridge journal at %s", p)
		}
		return Journal{}, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return Journal{}, fmt.Errorf("bridge journal is not valid JSON: %w", err)
	}
	if j.SchemaVersion != JournalSchema {
		return j, fmt.Errorf("bridge journal schema %d is not supported (want %d)", j.SchemaVersion, JournalSchema)
	}
	if j.State == "" {
		return j, fmt.Errorf("bridge journal has no state")
	}
	return j, nil
}

// writeJournal replaces the journal atomically and fsyncs the file and its
// directory so an abrupt process death cannot leave a truncated record.
func writeJournal(root string, j *Journal) error {
	j.SchemaVersion = JournalSchema
	j.Root = root
	if j.CreatedAt == "" {
		j.CreatedAt = now()
	}
	j.UpdatedAt = now()
	p, err := journalPath(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (j *Journal) step(name, detail string) {
	j.Steps = append(j.Steps, Step{Name: name, At: now(), Detail: detail})
}

func (j *Journal) setState(state, detail string) {
	j.State = state
	j.step(string(state), detail)
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hashFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return hashBytes(b), nil
}

// copyFileAtomic writes src to dst with fsync and a fixed mode.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}
