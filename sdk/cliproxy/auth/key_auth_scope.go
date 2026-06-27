package auth

import (
	"net/http"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

var defaultKeyAuthHeaders = []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key"}

type keyAuthScope struct {
	enabled bool
	scoped  bool
	deny    bool
	allowed map[string]struct{}
	err     error
}

func (s keyAuthScope) Active() bool {
	return s.enabled && (s.scoped || s.deny)
}

func (s keyAuthScope) Scoped() bool {
	return s.scoped
}

func (s keyAuthScope) Allow(authID string) bool {
	if !s.scoped {
		return true
	}
	_, ok := s.allowed[strings.TrimSpace(authID)]
	return ok
}

func (s keyAuthScope) Err() error {
	return s.err
}

func (m *Manager) keyAuthScope(opts cliproxyexecutor.Options) keyAuthScope {
	if m == nil {
		return keyAuthScope{}
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil || !cfg.Routing.KeyAuth.Enabled {
		return keyAuthScope{}
	}

	keyAuth := cfg.Routing.KeyAuth
	scope := keyAuthScope{enabled: true}
	clientKey := extractClientKeyFromHeaders(opts.Headers, keyAuthHeaders(keyAuth.KeyHeaders))
	binding, ok := lookupKeyAuthBinding(keyAuth.Bindings, clientKey)
	if ok {
		scope.scoped = true
		scope.allowed = authIDSet(binding.AuthIDs)
		return scope
	}

	if keyAuthDefaultPolicy(keyAuth.DefaultPolicy) == "deny" {
		scope.deny = true
		scope.err = &Error{Code: "auth_not_found", Message: "no auth bound for client key"}
	}
	return scope
}

func keyAuthHeaders(headers []string) []string {
	out := make([]string, 0, len(headers))
	seen := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		key := strings.ToLower(header)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, header)
	}
	if len(out) == 0 {
		return defaultKeyAuthHeaders
	}
	return out
}

func keyAuthDefaultPolicy(policy string) string {
	if strings.EqualFold(strings.TrimSpace(policy), "deny") {
		return "deny"
	}
	return "delegate"
}

func extractClientKeyFromHeaders(headers http.Header, keyHeaders []string) string {
	if len(headers) == 0 {
		return ""
	}
	for _, header := range keyHeaders {
		value := strings.TrimSpace(headers.Get(header))
		if value == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(header), "Authorization") {
			return extractAuthorizationKey(value)
		}
		return value
	}
	return ""
}

func extractAuthorizationKey(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(value[len("Bearer "):])
	}
	return value
}

func lookupKeyAuthBinding(bindings map[string]internalconfig.KeyAuthBinding, clientKey string) (internalconfig.KeyAuthBinding, bool) {
	clientKey = strings.TrimSpace(clientKey)
	if clientKey == "" {
		return internalconfig.KeyAuthBinding{}, false
	}
	if binding, ok := bindings[clientKey]; ok {
		return binding, true
	}
	for key, binding := range bindings {
		if strings.TrimSpace(key) == clientKey {
			return binding, true
		}
	}
	return internalconfig.KeyAuthBinding{}, false
}

func authIDSet(authIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(authIDs))
	for _, authID := range authIDs {
		authID = strings.TrimSpace(authID)
		if authID == "" {
			continue
		}
		out[authID] = struct{}{}
	}
	return out
}
