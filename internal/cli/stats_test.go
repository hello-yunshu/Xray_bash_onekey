package cli

import (
	"encoding/json"
	"testing"
)

func TestStatsListen(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]any
		want string
	}{
		{
			name: "api.listen string",
			doc: map[string]any{
				"api": map[string]any{"listen": "127.0.0.1:10085"},
			},
			want: "127.0.0.1:10085",
		},
		{
			name: "api.listen list",
			doc: map[string]any{
				"api": map[string]any{"listen": []any{"127.0.0.1:10086"}},
			},
			want: "127.0.0.1:10086",
		},
		{
			// The form written by `idleleo xray api enable`: no api.listen, the
			// endpoint is the inbound whose tag matches api.tag.
			name: "tagged api inbound",
			doc: map[string]any{
				"api": map[string]any{"tag": "api"},
				"inbounds": []any{
					map[string]any{"tag": "vless", "listen": "0.0.0.0", "port": float64(443)},
					map[string]any{"tag": "api", "listen": "127.0.0.1", "port": float64(10085)},
				},
			},
			want: "127.0.0.1:10085",
		},
		{
			name: "fallback to conventional api tag",
			doc: map[string]any{
				"inbounds": []any{
					map[string]any{"tag": "api", "port": float64(10086)},
				},
			},
			want: "127.0.0.1:10086",
		},
		{
			name: "wildcard inbound uses loopback",
			doc: map[string]any{
				"api": map[string]any{"tag": "api"},
				"inbounds": []any{
					map[string]any{"tag": "api", "listen": "0.0.0.0", "port": float64(10087)},
				},
			},
			want: "127.0.0.1:10087",
		},
		{
			name: "not configured",
			doc: map[string]any{
				"api": map[string]any{"tag": "api"},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statsListen(tt.doc); got != tt.want {
				t.Fatalf("statsListen() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCounterValue(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  float64
		ok    bool
	}{
		{name: "json number", value: float64(123), want: 123, ok: true},
		{name: "decimal string", value: "456", want: 456, ok: true},
		{name: "json number token", value: json.Number("789"), want: 789, ok: true},
		{name: "negative", value: float64(-1), ok: false},
		{name: "non numeric", value: "unknown", ok: false},
		{name: "other type", value: true, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := counterValue(tt.value)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Fatalf("counterValue(%v) = (%v, %t), want (%v, %t)", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}
