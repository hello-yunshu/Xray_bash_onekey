package netcfg

import (
	"errors"
	"testing"
)

func TestClassifyLiterals(t *testing.T) {
	good4 := []string{"1.2.3.4", " 203.0.113.7 ", "0.0.0.0"}
	bad4 := []string{"", "1.2.3", "1.2.3.4.5", "999.1.1.1", "01.2.3.4", "2001:db8::1", "[]"}
	for _, s := range good4 {
		if !IsIPv4Literal(s) {
			t.Errorf("IsIPv4Literal(%q) = false, want true", s)
		}
	}
	for _, s := range bad4 {
		if IsIPv4Literal(s) {
			t.Errorf("IsIPv4Literal(%q) = true, want false", s)
		}
	}
	good6 := []string{"2001:db8::1", "[2001:db8::1]", "::1", "fe80::1"}
	bad6 := []string{"", "1.2.3.4", "2001:db8::zz", "2001:db8::1%eth0"}
	for _, s := range good6 {
		if !IsIPv6Literal(s) {
			t.Errorf("IsIPv6Literal(%q) = false, want true", s)
		}
	}
	for _, s := range bad6 {
		if IsIPv6Literal(s) {
			t.Errorf("IsIPv6Literal(%q) = true, want false", s)
		}
	}
}

func TestClassifyKeepsOrderAndDuplicates(t *testing.T) {
	records := []string{"1.2.3.4\n2001:db8::2", "", "1.2.3.4", "not-an-ip"}
	v4, v6 := Classify(records)
	if len(v4) != 2 || v4[0] != "1.2.3.4" || v4[1] != "1.2.3.4" {
		t.Fatalf("v4 = %v, want [1.2.3.4 1.2.3.4]", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::2" {
		t.Fatalf("v6 = %v, want [2001:db8::2]", v6)
	}
}

func TestValidateTable(t *testing.T) {
	const (
		p4 = "1.2.3.4"
		p6 = "2001:db8::1"
	)
	cases := []struct {
		name    string
		policy  string
		records []string
		mode    string
		badA    bool
		badAAAA bool
		wantErr error
	}{
		{"dual", "auto", []string{p4, p6}, "dual", false, false, nil},
		{"a-ok-aaaa-foreign", "auto", []string{p4, "2001:db8::99"}, "ipv4", false, true, ErrBadRecords},
		{"aaaa-ok-a-foreign", "auto", []string{"1.2.3.99", p6}, "ipv6", true, false, ErrBadRecords},
		{"only-a", "auto", []string{p4}, "ipv4", false, false, nil},
		{"only-aaaa", "auto", []string{p6}, "ipv6", false, false, nil},
		{"no-match", "auto", []string{"9.9.9.9"}, "none", false, false, ErrNoMatch},
		{"explicit-ipv4-foreign-aaaa", "ipv4", []string{p4, "2001:db8::99"}, "ipv4", false, true, ErrBadRecords},
		{"explicit-ipv4-no-aaaa", "ipv4", []string{p4}, "ipv4", false, false, nil},
		{"explicit-ipv6-foreign-a", "ipv6", []string{"1.2.3.99", p6}, "ipv6", true, false, ErrBadRecords},
		{"explicit-ipv6-no-a", "ipv6", []string{p6}, "ipv6", false, false, nil},
		{"explicit-ipv4-no-a", "ipv4", []string{"1.2.3.99"}, "none", false, false, ErrNoMatch},
		{"empty", "auto", nil, "none", false, false, ErrNoMatch},
		{"canonical-equal", "auto", []string{"2001:0db8:0:0:0:0:0:1", p4}, "dual", false, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Validate(p4, p6, tc.records, tc.policy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if rep.Mode != tc.mode {
				t.Errorf("mode = %q, want %q", rep.Mode, tc.mode)
			}
			if rep.BadA != tc.badA || rep.BadAAAA != tc.badAAAA {
				t.Errorf("badA=%t badAAAA=%t, want %t/%t", rep.BadA, rep.BadAAAA, tc.badA, tc.badAAAA)
			}
		})
	}
}

func TestValidateWithoutServerAddress(t *testing.T) {
	rep, err := Validate("", "", []string{"1.2.3.4", "2001:db8::1"}, "auto")
	if !errors.Is(err, ErrNoMatch) || rep.Mode != "none" {
		t.Fatalf("rep=%+v err=%v, want mode none and ErrNoMatch", rep, err)
	}
}
