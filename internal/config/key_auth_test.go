package config

import "testing"

func TestParseConfigBytes_KeyAuthRouting(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
routing:
  strategy: fill-first
  key-auth:
    enabled: true
    default-policy: deny
    key-headers:
      - Authorization
      - X-Api-Key
    bindings:
      sk-client-a:
        auth-ids:
          - codex-a.json
          - codex-b.json
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if !cfg.Routing.KeyAuth.Enabled {
		t.Fatalf("Routing.KeyAuth.Enabled = false, want true")
	}
	if cfg.Routing.KeyAuth.DefaultPolicy != "deny" {
		t.Fatalf("Routing.KeyAuth.DefaultPolicy = %q, want deny", cfg.Routing.KeyAuth.DefaultPolicy)
	}
	if got := cfg.Routing.KeyAuth.KeyHeaders; len(got) != 2 || got[0] != "Authorization" || got[1] != "X-Api-Key" {
		t.Fatalf("Routing.KeyAuth.KeyHeaders = %#v", got)
	}
	binding := cfg.Routing.KeyAuth.Bindings["sk-client-a"]
	if len(binding.AuthIDs) != 2 || binding.AuthIDs[0] != "codex-a.json" || binding.AuthIDs[1] != "codex-b.json" {
		t.Fatalf("Routing.KeyAuth.Bindings[sk-client-a] = %#v", binding)
	}
}
