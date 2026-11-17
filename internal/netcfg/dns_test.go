package netcfg

import (
	"context"
	"testing"
)

func TestLookupRejectsEmptyDomain(t *testing.T) {
	if _, err := Lookup(context.Background(), "  ", ""); err == nil {
		t.Fatal("Lookup accepted an empty domain")
	}
}

func TestLocalPublicIPsTypes(t *testing.T) {
	v4, v6 := LocalPublicIPs()
	if v4 != "" && !IsIPv4Literal(v4) {
		t.Errorf("LocalPublicIPs v4 = %q, want an IPv4 literal", v4)
	}
	if v6 != "" && !IsIPv6Literal(v6) {
		t.Errorf("LocalPublicIPs v6 = %q, want an IPv6 literal", v6)
	}
}
