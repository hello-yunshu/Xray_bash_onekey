package schedule

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Alert is the durable record of a failed scheduled job. It is written under
// etc/idleleo/alerts and read by `idleleo status` before any other field.
type Alert struct {
	SchemaVersion int    `json:"schemaVersion"`
	Job           string `json:"job"`
	Result        string `json:"result"`
	Detail        string `json:"detail"`
	At            string `json:"at"`
	Webhook       string `json:"webhook,omitempty"`
}

var alertJobPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func alertRel(job string) string {
	if !alertJobPattern.MatchString(job) {
		job = "invalid"
	}
	return AlertsDirRel + "/" + job + ".json"
}

// WriteAlert persists the alert and, when configured, POSTs it to the webhook.
// The persisted file is the only durable signal `idleleo status` can read, so an
// encoding or write failure is returned instead of being swallowed: callers must
// be able to tell "no alert" apart from "alert lost".
func WriteAlert(ctx context.Context, root string, cfg Config, job, result, detail, at string) (Alert, error) {
	a := Alert{SchemaVersion: SchemaVersion, Job: job, Result: result, Detail: detail, At: at}
	if cfg.AlertWebhook != "" {
		a.Webhook = postAlertWebhook(ctx, cfg.AlertWebhook, a)
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return a, fmt.Errorf("encode alert %s: %w", job, err)
	}
	if err := writeAtomic(path(root, alertRel(job)), append(b, '\n'), 0o640); err != nil {
		return a, fmt.Errorf("persist alert %s: %w", job, err)
	}
	return a, nil
}

// RecordAlert loads the persisted config and writes a failed-job alert. It is
// used by the systemd OnFailure hook (`schedule alert`) and by callers that do
// not already hold a Config.
func RecordAlert(ctx context.Context, root, job, detail, at string) (Alert, error) {
	cfg, _ := loadConfig(root)
	return WriteAlert(ctx, root, cfg, job, "failed", detail, at)
}

// ClearAlert removes a stale alert after a successful run.
func ClearAlert(root, job string) error {
	err := os.Remove(path(root, alertRel(job)))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Alerts returns every readable alert, sorted by job name. A missing alert
// directory means "no alerts yet" and is not an error. Any other failure (an
// unreadable directory, or an unreadable/corrupt alert file) is returned as
// well as the alerts that did parse, because silently dropping a record would
// make a lost alert look exactly like a clean state.
func Alerts(root string) ([]Alert, error) {
	dir := path(root, AlertsDirRel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read alerts directory: %w", err)
	}
	out := []Alert{}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			note(fmt.Errorf("read alert %s: %w", entry.Name(), err))
			continue
		}
		var a Alert
		if err := json.Unmarshal(b, &a); err != nil {
			note(fmt.Errorf("parse alert %s: %w", entry.Name(), err))
			continue
		}
		if a.Job == "" {
			note(fmt.Errorf("parse alert %s: missing job", entry.Name()))
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Job < out[j].Job })
	return out, firstErr
}

func postAlertWebhook(ctx context.Context, url string, a Alert) string {
	body, err := json.Marshal(map[string]string{
		"job": a.Job, "result": a.Result, "detail": a.Detail, "at": a.At,
	})
	if err != nil {
		return "encode-error: " + err.Error()
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "request-error: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "posted"
}
