package deploy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// streamFixture writes an executable shell shim at dir/sbin/nginx and returns
// its absolute path. The module candidate path is created next to it.
func streamFixture(t *testing.T, script string) (bin, module string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "sbin", "nginx")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	module = filepath.Join(filepath.Dir(bin), "..", "lib", "nginx", "modules", "ngx_stream_module.so")
	if err := os.MkdirAll(filepath.Dir(module), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	return bin, module
}

func TestStreamModuleUsesHostRunAndDetectsDynamicBuild(t *testing.T) {
	bin, module := streamFixture(t, "#!/bin/sh\necho 'nginx version: nginx/1.24.0'\necho 'configure arguments: --with-stream=dynamic --with-http_ssl_module'\n")
	got := streamModule(context.Background(), bin)
	if got != module {
		t.Fatalf("streamModule=%q, want %q", got, module)
	}
}

func TestStreamModuleFailsWhenNginxWasBuiltWithoutStream(t *testing.T) {
	bin, _ := streamFixture(t, "#!/bin/sh\necho 'configure arguments: --with-http_ssl_module'\n")
	if got := streamModule(context.Background(), bin); got != "" {
		t.Fatalf("streamModule=%q, want empty", got)
	}
}

func TestStreamModuleHonoursTimeout(t *testing.T) {
	bin, _ := streamFixture(t, "#!/bin/sh\nsleep 30\necho '--with-stream=dynamic'\n")
	previous := moduleProbeTimeout
	moduleProbeTimeout = 200 * time.Millisecond
	defer func() { moduleProbeTimeout = previous }()

	start := time.Now()
	got := streamModule(context.Background(), bin)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("streamModule blocked for %s; timeout not applied", elapsed)
	}
	if got != "" {
		t.Fatalf("streamModule=%q, want empty after timeout", got)
	}
}

func TestStreamModuleDoesNotUseCallerPATH(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "nginx")
	script := "#!/bin/sh\ntouch " + marker + "\necho 'configure arguments: --with-stream=dynamic'\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if got := streamModule(context.Background(), "nginx"); got != "" {
		t.Fatalf("streamModule=%q, want empty (caller PATH must not resolve)", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("caller PATH shim was executed; host.Run must use the fixed PATH")
	}
}
