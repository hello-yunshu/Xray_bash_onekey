// Command parity-adapter exposes the production internal/compat package to
// the Phase 00 L0 differential harness. It is not a management entrypoint.
package main

import (
	"fmt"
	"os"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: parity-adapter operation arg [arg]")
		os.Exit(4)
	}
	out, rc, err := compat.RunOp(os.Args[1], os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	fmt.Print(out)
	os.Exit(rc)
}
