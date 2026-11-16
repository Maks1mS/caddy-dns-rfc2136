package caddy_dns_rfc2136

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/rfc2136"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNet string
		wantErr bool
	}{
		{
			name: "full config with udp",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
				server "1.2.3.4:53"
				net "udp"
			}`,
			wantNet: "udp",
		},
		{
			name: "full config with tcp",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
				server "1.2.3.4:53"
				net "tcp"
			}`,
			wantNet: "tcp",
		},
		{
			name: "no net defaults to empty",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
				server "1.2.3.4:53"
			}`,
			wantNet: "",
		},
		{
			name: "invalid net",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
				server "1.2.3.4:53"
				net "unix"
			}`,
			wantErr: true,
		},
		{
			name: "missing key",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				server "1.2.3.4:53"
			}`,
			wantErr: true,
		},
		{
			name: "unrecognized subdirective",
			input: `rfc2136 {
				key_name "test"
				key_alg "hmac-sha256"
				key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
				server "1.2.3.4:53"
				unknown "value"
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{new(rfc2136.Provider)}
			d := caddyfile.NewTestDispenser(tt.input)

			err := p.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Net != tt.wantNet {
				t.Fatalf("got net %q, want %q", p.Net, tt.wantNet)
			}
		})
	}
}
