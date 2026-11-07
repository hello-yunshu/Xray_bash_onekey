package main

import (
	"encoding/json"
	"errors"
	"example.org/idleleo/bridge-probe-v2/bridge"
	"flag"
	"fmt"
	"os"
	"runtime"
)

func main() {
	// Executable preflight: only the exact expected protocol reply is accepted.
	if len(os.Args) == 2 && os.Args[1] == "--bridge-self-check" {
		b, _ := json.Marshal(map[string]any{"protocol": bridge.Protocol, "schema": 2, "goos": runtime.GOOS, "goarch": runtime.GOARCH})
		fmt.Println(string(b))
		return
	}
	root := flag.String("root", "", "disposable sandbox root with marker")
	mode := flag.String("mode", "inspect", "inspect|prepare|activate|recover|status")
	pin := flag.String("candidate-sha256", "", "SHA256 from an independently trusted release manifest")
	fault := flag.String("fault", "", "test-only interruption injection")
	flag.Parse()
	var out any
	var e error
	switch *mode {
	case "inspect":
		out, e = bridge.Inspect(*root)
	case "prepare":
		out, e = bridge.Prepare(*root, *pin, *fault)
	case "activate":
		out, e = bridge.Activate(*root, *fault)
	case "recover":
		out, e = bridge.Recover(*root)
	case "status":
		out, e = bridge.Status(*root)
	default:
		e = fmt.Errorf("unknown mode: %q", *mode)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "PROBE_V2_ERROR:", e)
		if errors.Is(e, bridge.ErrInterrupted) {
			os.Exit(86)
		}
		os.Exit(2)
	}
	b, e := json.MarshalIndent(out, "", "  ")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(3)
	}
	fmt.Println(string(b))
}
