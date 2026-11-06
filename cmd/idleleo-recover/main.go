// Command idleleo-recover is the independent recovery entry installed at
// /opt/idleleo/recovery/idleleo-recover. It reads the bridge journal with the
// standard library only, so it keeps working even when the main entry is
// broken or half-switched.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/legacybridge"
)

func main() {
	root := flag.String("root", "/", "bridge root")
	container := flag.Bool("container", false, "allow writes to the real root inside a container")
	jsonOut := flag.Bool("json", false, "print the recovery report as JSON")
	flag.Parse()

	report, err := legacybridge.Recover(legacybridge.RecoverOptions{
		Root:                 *root,
		AllowContainerWrites: *container,
	})
	b, _ := json.MarshalIndent(report, "", "  ")
	if *jsonOut {
		fmt.Println(string(b))
	}
	var be *legacybridge.Error
	if errors.As(err, &be) {
		fmt.Fprintln(os.Stderr, be.Error())
		os.Exit(be.Code)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
