package compat

import "testing"

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b, out string
		rc        int
	}{
		{"1.2.3", "1.2.3", "0\n", 0},
		{"1.10", "1.9", "1\n", 0},
		{"v2.0", "1.99", "1\n", 0},
		{"1.2", "1.2.0", "0\n", 0},
		{"abc", "1.0", "", 2},
		{"1..2", "1.0", "", 2},
	}
	for _, c := range cases {
		out, rc := VersionCompare(c.a, c.b)
		if out != c.out || rc != c.rc {
			t.Fatalf("VersionCompare(%q,%q)=%q,%d want %q,%d", c.a, c.b, out, rc, c.out, c.rc)
		}
	}
}

func TestVersionSeriesDifference(t *testing.T) {
	if out, _ := VersionSeriesDifference("3.3.4", "3.3.5"); out != "0\n" {
		t.Fatalf("same series: %q", out)
	}
	if out, _ := VersionSeriesDifference("3.3.4", "3.4.0"); out != "1\n" {
		t.Fatalf("different series: %q", out)
	}
	if out, _ := VersionSeriesDifference("3.03.1", "3.3.0"); out != "1\n" {
		t.Fatalf("string series comparison: %q", out)
	}
}

func TestRelayHost(t *testing.T) {
	valid := []string{"example.com", "a-b.example.com", "192.0.2.1", "2001:db8::1", "[2001:db8::1]"}
	invalid := []string{"", "example..com", "-bad.com", "bad-.com", "a b", "123"}
	for _, s := range valid {
		if !RelayIsValidHost(s) {
			t.Errorf("expected valid: %q", s)
		}
	}
	for _, s := range invalid {
		if RelayIsValidHost(s) {
			t.Errorf("expected invalid: %q", s)
		}
	}
}

func TestFormatters(t *testing.T) {
	if got := FormatXHTTPPath("foo"); got != "/foo\n" {
		t.Fatalf("xhttp: %q", got)
	}
	if got := FormatURIAuthorityHost("2001:db8::1"); got != "[2001:db8::1]\n" {
		t.Fatalf("authority v6: %q", got)
	}
	if got := FormatURIAuthorityHost("example.com"); got != "example.com\n" {
		t.Fatalf("authority host: %q", got)
	}
	if got := YAMLQuoteScalar("2001:db8::1"); got != "'2001:db8::1'\n" {
		t.Fatalf("yaml v6: %q", got)
	}
	if got := VLESSURLQuote("a b/c"); got != "a%20b/c\n" {
		t.Fatalf("urlquote: %q", got)
	}
}

func TestRunOpUnknown(t *testing.T) {
	if _, rc, err := RunOp("nope", nil); err == nil || rc != 4 {
		t.Fatalf("unknown op: rc=%d err=%v", rc, err)
	}
}
