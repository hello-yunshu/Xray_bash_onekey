// compatprobe is a TEST IMPLEMENTATION of selected Bash pure functions.
// It is not the production idleleo Go CLI and it doesn't implement Xray deployment.
package main

import (
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var numeric = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
var digits = regexp.MustCompile(`^[0-9]+$`)
var domain = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func trimV(v string) string { return strings.TrimPrefix(v, "v") }
func compare(a, b string) (string, int) {
	a, b = trimV(a), trimV(b)
	if !numeric.MatchString(a) || !numeric.MatchString(b) {
		return "", 2
	}
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	n := len(x)
	if len(y) > n {
		n = len(y)
	}
	for i := 0; i < n; i++ {
		aa, bb := big.NewInt(0), big.NewInt(0)
		if i < len(x) {
			aa.SetString(x[i], 10)
		}
		if i < len(y) {
			bb.SetString(y[i], 10)
		}
		c := aa.Cmp(bb)
		if c > 0 {
			return "1\n", 0
		}
		if c < 0 {
			return "-1\n", 0
		}
	}
	return "0\n", 0
}
func series(a, b string) (string, int) {
	a, b = trimV(a), trimV(b)
	if !numeric.MatchString(a) || !numeric.MatchString(b) {
		return "0\n", 0
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	amin, bmin := "", ""
	if len(aa) > 1 {
		amin = aa[1]
	} else {
		amin = aa[0]
	}
	if len(bb) > 1 {
		bmin = bb[1]
	} else {
		bmin = bb[0]
	}
	// Mirrors Bash's string comparison; e.g. 03 and 3 differ here.
	if aa[0] != bb[0] || amin != bmin {
		return "1\n", 0
	}
	return "0\n", 0
}
func ipLiteral(s string, v6 bool) bool {
	if s == "" {
		return false
	}
	if v6 {
		if !strings.Contains(s, ":") {
			return false
		}
	} else {
		if !strings.Contains(s, ".") || strings.Contains(s, ":") {
			return false
		}
	}
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil // Bash tests colon/dot before ipaddress.ip_address, not the parsed family.
}
func relayHost(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 253 {
		return false
	}
	if ipLiteral(s, true) || ipLiteral(s, false) {
		return true
	}
	if digits.MatchString(s) {
		return false
	}
	if !domain.MatchString(s) || strings.Contains(s, "..") || strings.Contains(s, ".-") || strings.Contains(s, "-.") {
		return false
	}
	return true
}
func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: compatprobe operation arg [arg]")
		os.Exit(4)
	}
	op, a := os.Args[1], os.Args[2]
	b := ""
	if len(os.Args) > 3 {
		b = os.Args[3]
	}
	var out string
	rc := 0
	switch op {
	case "version_compare":
		out, rc = compare(a, b)
	case "version_series_difference":
		out, rc = series(a, b)
	case "relay_is_valid_host":
		if !relayHost(a) {
			rc = 1
		}
	case "format_xhttp_path":
		out = "/" + strings.TrimPrefix(a, "/") + "\n"
	case "format_uri_authority_host":
		if ipLiteral(a, true) {
			out = "[" + strings.TrimSuffix(strings.TrimPrefix(a, "["), "]") + "]\n"
		} else {
			out = a + "\n"
		}
	case "yaml_quote_scalar":
		if ipLiteral(a, true) {
			out = "'" + a + "'\n"
		} else {
			out = a + "\n"
		}
	case "vless_urlquote":
		out = strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(a), "+", "%20"), "%2F", "/") + "\n"
	default:
		fmt.Fprintln(os.Stderr, "unknown op")
		os.Exit(4)
	}
	fmt.Print(out)
	os.Exit(rc)
}
