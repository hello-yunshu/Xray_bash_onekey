package legacybridge

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RillStatus is the read-only `idleleo rill status` projection. It works on
// both Go-managed and legacy installations because it only reads the agent's
// own paths; it never requires install_config.json.
func RillStatus(root string) RillInfo {
	info, _ := projectRill(root)
	return info
}

// projectRill returns the projection plus the warnings that the migration
// audit should surface. Private content is never copied, only hashed.
func projectRill(root string) (RillInfo, []Finding) {
	info := RillInfo{Status: "absent", Enabled: false}
	findings := []Finding{}
	cfgPath := mustResolve(root, rillConfigRel)
	obsPath := mustResolve(root, rillObservationRel)
	binPath := mustResolve(root, rillBinaryRel)

	installed := false
	if _, err := os.Stat(binPath); err == nil {
		installed = true
		info.Binary = rillBinaryRel
	}
	if b, err := os.ReadFile(cfgPath); err == nil {
		installed = true
		info.ConfigPath = rillConfigRel
		info.ConfigSHA256 = hashBytes(b)
		info.Enabled = true
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err == nil {
			info.Mode = rillMode(doc)
			if v, ok := doc["enabled"].(bool); ok {
				info.Enabled = v
			}
		} else {
			info.Warning = "config.json is not valid JSON"
			findings = append(findings, Finding{Code: "rill-config-unreadable", Severity: severityWarn,
				Message: "Rill config.json is present but not valid JSON"})
		}
	}
	if !installed {
		return info, findings
	}
	info.Installed = true
	b, err := os.ReadFile(obsPath)
	if err != nil {
		info.Status = "installed-unobserved"
		info.Warning = "no xray-observation.json yet"
		findings = append(findings, Finding{Code: "rill-observation-missing", Severity: severityWarn,
			Message: "Rill is installed but has no xray observation"})
		return info, findings
	}
	info.ObservationPath = rillObservationRel
	info.ObservationSHA256 = hashBytes(b)
	observed := observationTime(b)
	if observed.IsZero() {
		if fi, err := os.Stat(obsPath); err == nil {
			observed = fi.ModTime()
		}
	}
	age := int64(time.Since(observed).Seconds())
	if age < 0 {
		age = 0
	}
	info.ObservationAgeSeconds = age
	if age <= rillFreshSeconds {
		info.Status = "active"
	} else {
		info.Status = "stale"
		info.Warning = fmt.Sprintf("last observation is %d seconds old", age)
		findings = append(findings, Finding{Code: "rill-observation-stale", Severity: severityWarn,
			Message: fmt.Sprintf("Rill observation is %d seconds old (freshness limit %ds)", age, rillFreshSeconds)})
	}
	return info, findings
}
