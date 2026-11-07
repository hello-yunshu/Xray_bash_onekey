// Package compat implements the seven pure Bash functions that Phase 00
// pinned as L0 contracts. Production display code and the parity adapter
// both import this package so the differential test exercises real code.
package compat

import (
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var numeric = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
var digits = regexp.MustCompile(`^[0-9]+$`)
var domain = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func trimV(v string) string { return strings.TrimPrefix(v, "v") }

// VersionCompare mirrors Bash version_compare. It returns "1\n", "-1\n" or
// "0\n" and a non-zero code for invalid numeric versions.
func VersionCompare(a, b string) (string, int) {
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

// VersionSeriesDifference mirrors Bash's string comparison, including the
// fact that "03" and "3" differ.
func VersionSeriesDifference(a, b string) (string, int) {
	a, b = trimV(a), trimV(b)
	if !numeric.MatchString(a) || !numeric.MatchString(b) {
		return "0\n", 0
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	amin, bmin := aa[0], bb[0]
	if len(aa) > 1 {
		amin = aa[1]
	}
	if len(bb) > 1 {
		bmin = bb[1]
	}
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
	} else if !strings.Contains(s, ".") || strings.Contains(s, ":") {
		return false
	}
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// RelayIsValidHost mirrors Bash relay_is_valid_host.
func RelayIsValidHost(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 253 {
		return false
	}
	if ipLiteral(s, true) || ipLiteral(s, false) {
		return true
	}
	if digits.MatchString(s) {
		return false
	}
	if !domain.MatchString(s) || strings.Contains(s, "..") ||
		strings.Contains(s, ".-") || strings.Contains(s, "-.") {
		return false
	}
	return true
}

// FormatXHTTPPath mirrors Bash format_xhttp_path.
func FormatXHTTPPath(s string) string {
	return "/" + strings.TrimPrefix(s, "/") + "\n"
}

// FormatURIAuthorityHost brackets IPv6 literals for VLESS authorities.
func FormatURIAuthorityHost(s string) string {
	if ipLiteral(s, true) {
		return "[" + strings.TrimSuffix(strings.TrimPrefix(s, "["), "]") + "]\n"
	}
	return s + "\n"
}

// YAMLQuoteScalar quotes IPv6 literals with single quotes.
func YAMLQuoteScalar(s string) string {
	if ipLiteral(s, true) {
		return "'" + s + "'\n"
	}
	return s + "\n"
}

// VLESSURLQuote mirrors Bash vless_urlquote.
func VLESSURLQuote(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"), "%2F", "/") + "\n"
}

// SupportedOps lists the operation names accepted by the parity adapter.
var SupportedOps = []string{
	"version_compare",
	"version_series_difference",
	"relay_is_valid_host",
	"format_uri_authority_host",
	"yaml_quote_scalar",
	"format_xhttp_path",
	"vless_urlquote",
}

// RunOp executes one L0 operation and returns stdout plus exit code. It is
// shared by the adapter and unit tests so the parity path is not a reimplementation.
func RunOp(op string, args []string) (string, int, error) {
	a, b := "", ""
	if len(args) > 0 {
		a = args[0]
	}
	if len(args) > 1 {
		b = args[1]
	}
	switch op {
	case "version_compare":
		out, rc := VersionCompare(a, b)
		return out, rc, nil
	case "version_series_difference":
		out, rc := VersionSeriesDifference(a, b)
		return out, rc, nil
	case "relay_is_valid_host":
		if !RelayIsValidHost(a) {
			return "", 1, nil
		}
		return "", 0, nil
	case "format_xhttp_path":
		return FormatXHTTPPath(a), 0, nil
	case "format_uri_authority_host":
		return FormatURIAuthorityHost(a), 0, nil
	case "yaml_quote_scalar":
		return YAMLQuoteScalar(a), 0, nil
	case "vless_urlquote":
		return VLESSURLQuote(a), 0, nil
	default:
		return "", 4, fmt.Errorf("unknown op: %s", op)
	}
}
