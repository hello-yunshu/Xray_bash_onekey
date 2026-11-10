package legacybridge

import (
	"context"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// CandidateManifest is the trusted description of the Go manager that is
// allowed to replace the legacy entry. It is produced by the release channel,
// not by the candidate itself, so a tampered binary cannot supply its own
// approval.
type CandidateManifest struct {
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256"`
	GOARCH  string `json:"goarch,omitempty"`
}

// candidateVersionTimeout bounds the self-check so a hanging candidate cannot
// block migration forever.
const candidateVersionTimeout = 10 * time.Second

// verifyCandidate replaces the old "regular file + executable bit" check.
// A text file with chmod +x, a binary for another architecture, a digest that
// does not match the trusted manifest, or a binary that does not identify
// itself as idleleo are all rejected.
func verifyCandidate(ctx context.Context, path, manifestPath string) (sha string, version string, warnings []string, err error) {
	if err := runnableFile(path); err != nil {
		return "", "", nil, fmt.Errorf("candidate is not an executable file: %w", err)
	}
	if err := requireELFArch(path); err != nil {
		return "", "", nil, err
	}
	sha, err = hashFile(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("candidate hash failed: %w", err)
	}

	var manifest *CandidateManifest
	if manifestPath != "" {
		m, err := readCandidateManifest(manifestPath)
		if err != nil {
			return "", "", nil, err
		}
		manifest = &m
		if err := checkManifestDigest(m, sha); err != nil {
			return "", "", nil, err
		}
		if m.GOARCH != "" && m.GOARCH != runtime.GOARCH {
			return "", "", nil, fmt.Errorf("trusted manifest targets %s but this host is %s", m.GOARCH, runtime.GOARCH)
		}
	}

	version, err = candidateSelfVersion(ctx, path)
	if err != nil {
		return "", "", nil, err
	}
	if manifest != nil && manifest.Version != "" && manifest.Version != version {
		return "", "", nil, fmt.Errorf("candidate reports version %q but the trusted manifest requires %q", version, manifest.Version)
	}
	if manifest == nil {
		warnings = append(warnings, "candidate-unpinned: no --candidate-manifest given; sha256 "+sha+" was computed locally and is not compared with a trusted release manifest")
	}
	return sha, version, warnings, nil
}

func readCandidateManifest(p string) (CandidateManifest, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return CandidateManifest{}, fmt.Errorf("read candidate manifest: %w", err)
	}
	var m CandidateManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return CandidateManifest{}, fmt.Errorf("candidate manifest is not valid JSON: %w", err)
	}
	m.SHA256 = strings.ToLower(strings.TrimSpace(m.SHA256))
	if m.SHA256 == "" {
		return CandidateManifest{}, errors.New("candidate manifest has no sha256")
	}
	if len(m.SHA256) != 64 {
		return CandidateManifest{}, fmt.Errorf("candidate manifest sha256 must be 64 hex characters, got %d", len(m.SHA256))
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return CandidateManifest{}, fmt.Errorf("candidate manifest sha256 is not hex: %w", err)
	}
	return m, nil
}

func checkManifestDigest(m CandidateManifest, actual string) error {
	if !strings.EqualFold(m.SHA256, actual) {
		return fmt.Errorf("candidate sha256 %s does not match the trusted manifest %s", actual, m.SHA256)
	}
	return nil
}

// requireELFArch rejects anything that is not a native ELF binary. This is the
// check that stops "chmod +x notes.txt" from being accepted as the Go manager.
func requireELFArch(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("candidate is not an ELF binary: %w", err)
	}
	defer f.Close()
	got, err := goarchForELF(f.Class, f.Machine)
	if err != nil {
		return err
	}
	if got != runtime.GOARCH {
		return fmt.Errorf("candidate architecture %s does not match this host (%s)", got, runtime.GOARCH)
	}
	return nil
}

func goarchForELF(class elf.Class, machine elf.Machine) (string, error) {
	switch machine {
	case elf.EM_X86_64:
		if class != elf.ELFCLASS64 {
			return "", fmt.Errorf("candidate ELF class %s is inconsistent with %s", class, machine)
		}
		return "amd64", nil
	case elf.EM_AARCH64:
		if class != elf.ELFCLASS64 {
			return "", fmt.Errorf("candidate ELF class %s is inconsistent with %s", class, machine)
		}
		return "arm64", nil
	case elf.EM_386:
		if class != elf.ELFCLASS32 {
			return "", fmt.Errorf("candidate ELF class %s is inconsistent with %s", class, machine)
		}
		return "386", nil
	case elf.EM_ARM:
		return "arm", nil
	case elf.EM_PPC64:
		return "ppc64le", nil
	case elf.EM_S390:
		return "s390x", nil
	case elf.EM_RISCV:
		return "riscv64", nil
	default:
		return "", fmt.Errorf("candidate ELF machine %s is not supported on this host (%s)", machine, runtime.GOARCH)
	}
}

// candidateSelfVersion runs `<candidate> version` and requires the binary to
// identify itself as idleleo. Running the candidate is the only way to prove
// that the bytes are a working manager and not an arbitrary executable.
func candidateSelfVersion(ctx context.Context, path string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, candidateVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, "version")
	out, err := cmd.Output()
	if err != nil {
		if cctx.Err() != nil {
			return "", fmt.Errorf("candidate version self-check timed out after %s", candidateVersionTimeout)
		}
		return "", fmt.Errorf("candidate version self-check failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "idleleo" {
			continue
		}
		return fields[1], nil
	}
	return "", errors.New("candidate version self-check did not print an idleleo version")
}
