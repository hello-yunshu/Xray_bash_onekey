// Package netcfg implements the dual-stack DNS validation and the managed
// netfilter port reconciliation that the Bash installer performs inline.
package netcfg

import (
	"errors"
	"net"
	"strings"
)

// ErrBadRecords marks a domain whose A/AAAA set points at another host for a
// family that is otherwise usable. The CLI maps it to exit code 2 because the
// operator must confirm before the install continues.
var ErrBadRecords = errors.New("domain resolves to a foreign address for an enabled family")

// ErrNoMatch marks a domain that resolves to nothing usable for this server.
var ErrNoMatch = errors.New("no resolved address family matches this server")

// IsIPv4Literal reports whether s is a bare IPv4 address. It mirrors Bash
// is_ipv4_literal: a dot is required, a colon disqualifies, and every octet
// must be 0-255 (net.ParseIP rejects 999.1.1.1 and leading zeros).
func IsIPv4Literal(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !strings.Contains(s, ".") || strings.Contains(s, ":") {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// IsIPv6Literal reports whether s is a bare or bracket-wrapped IPv6 address.
func IsIPv6Literal(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !strings.Contains(s, ":") {
		return false
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// canonical returns the compressed form of an IP literal, or "" when the
// input is not a valid address. Comparison uses canonical forms so
// 2001:db8::1 and 2001:0db8:0:0:0:0:0:1 are the same address.
func canonical(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// Classify splits records into IPv4 and IPv6 lists, preserving input order and
// skipping empty entries. It never deduplicates, matching classify_resolved_ips.
func Classify(records []string) (v4, v6 []string) {
	for _, raw := range records {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case line == "":
			case IsIPv6Literal(line):
				v6 = append(v6, line)
			case IsIPv4Literal(line):
				v4 = append(v4, line)
			}
		}
	}
	return v4, v6
}

// DNSReport is the structured result of one dual-stack qualification.
type DNSReport struct {
	Mode    string `json:"mode"`
	HasA    bool   `json:"hasA"`
	HasAAAA bool   `json:"hasAAAA"`
	AOK     bool   `json:"aOK"`
	AAAAOK  bool   `json:"aaaaOK"`
	BadA    bool   `json:"badA"`
	BadAAAA bool   `json:"badAAAA"`
}

// Validate reproduces validate_domain_network_records step for step.
//
// A family is usable only when the server has a public address for it AND at
// least one resolved record of that family matches it. An explicit policy still
// reports a foreign record of the other family as bad: selecting IPv4 must not
// bypass the AAAA safety check.
func Validate(public4, public6 string, records []string, policy string) (DNSReport, error) {
	v4, v6 := Classify(records)
	rep := DNSReport{
		Mode:    "none",
		HasA:    len(v4) > 0,
		HasAAAA: len(v6) > 0,
	}
	if wanted := canonical(public4); wanted != "" {
		rep.AOK = contains(v4, wanted)
	}
	if wanted := canonical(public6); wanted != "" {
		rep.AAAAOK = contains(v6, wanted)
	}

	switch policy {
	case "ipv4":
		if rep.AOK {
			rep.Mode = "ipv4"
			if rep.HasAAAA && !rep.AAAAOK {
				rep.BadAAAA = true
			}
		}
	case "ipv6":
		if rep.AAAAOK {
			rep.Mode = "ipv6"
			if rep.HasA && !rep.AOK {
				rep.BadA = true
			}
		}
	default:
		switch {
		case rep.AOK && rep.AAAAOK:
			rep.Mode = "dual"
		case rep.AOK:
			rep.Mode = "ipv4"
			if rep.HasAAAA {
				rep.BadAAAA = true
			}
		case rep.AAAAOK:
			rep.Mode = "ipv6"
			if rep.HasA {
				rep.BadA = true
			}
		}
	}

	if rep.BadA || rep.BadAAAA {
		return rep, ErrBadRecords
	}
	if rep.Mode == "none" {
		return rep, ErrNoMatch
	}
	return rep, nil
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if canonical(item) == want {
			return true
		}
	}
	return false
}
