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
// Persistence errors are ignored: an alert must never turn a job result into a
// crash, and the caller still returns the original failure.
func WriteAlert(ctx context.Context, root string, cfg Config, job, result, detail, at string) Alert {
	a := Alert{SchemaVersion: SchemaVersion, Job: job, Result: result, Detail: detail, At: at}
	if cfg.AlertWebhook != "" {
		a.Webhook = postAlertWebhook(ctx, cfg.AlertWebhook, a)
	}
	if b, err := json.MarshalIndent(a, "", "  "); err == nil {
		_ = writeAtomic(path(root, alertRel(job)), append(b, '\n'), 0o640)
	}
	return a
}

// RecordAlert loads the persisted config and writes a failed-job alert. It is
// used by the systemd OnFailure hook (`schedule alert`) and by callers that do
// not already hold a Config.
func RecordAlert(ctx context.Context, root, job, detail, at string) Alert {
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

// Alerts returns every readable alert, sorted by job name.
func Alerts(root string) []Alert {
	dir := path(root, AlertsDirRel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []Alert{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var a Alert
		if json.Unmarshal(b, &a) != nil || a.Job == "" {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Job < out[j].Job })
	return out
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
