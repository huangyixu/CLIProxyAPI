package auth

import (
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestKeyAuthScope(t *testing.T) {
	tests := []struct {
		name        string
		config      internalconfig.KeyAuthRoutingConfig
		headers     http.Header
		wantActive  bool
		wantScoped  bool
		wantAllowed map[string]bool
		wantErrCode string
	}{
		{
			name: "disabled allows all",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled: false,
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"sk-client": {AuthIDs: []string{"auth-a"}},
				},
			},
			headers:     http.Header{"Authorization": []string{"Bearer sk-client"}},
			wantAllowed: map[string]bool{"auth-a": true, "auth-b": true},
		},
		{
			name: "authorization bearer scoped",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled: true,
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"sk-client": {AuthIDs: []string{" auth-a ", "auth-b", "auth-a", ""}},
				},
			},
			headers:     http.Header{"Authorization": []string{"Bearer sk-client"}},
			wantActive:  true,
			wantScoped:  true,
			wantAllowed: map[string]bool{"auth-a": true, "auth-b": true, "auth-c": false},
		},
		{
			name: "authorization raw scoped",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled: true,
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"raw-key": {AuthIDs: []string{"auth-a"}},
				},
			},
			headers:     http.Header{"Authorization": []string{"raw-key"}},
			wantActive:  true,
			wantScoped:  true,
			wantAllowed: map[string]bool{"auth-a": true, "auth-b": false},
		},
		{
			name: "x api key scoped",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled: true,
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"x-key": {AuthIDs: []string{"auth-x"}},
				},
			},
			headers:     http.Header{"X-Api-Key": []string{"x-key"}},
			wantActive:  true,
			wantScoped:  true,
			wantAllowed: map[string]bool{"auth-x": true, "auth-y": false},
		},
		{
			name: "x goog api key scoped",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled: true,
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"goog-key": {AuthIDs: []string{"auth-g"}},
				},
			},
			headers:     http.Header{"X-Goog-Api-Key": []string{"goog-key"}},
			wantActive:  true,
			wantScoped:  true,
			wantAllowed: map[string]bool{"auth-g": true, "auth-z": false},
		},
		{
			name: "configured header order",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled:    true,
				KeyHeaders: []string{"X-Api-Key", "Authorization"},
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"x-key":    {AuthIDs: []string{"auth-x"}},
					"auth-key": {AuthIDs: []string{"auth-a"}},
				},
			},
			headers:     http.Header{"Authorization": []string{"Bearer auth-key"}, "X-Api-Key": []string{"x-key"}},
			wantActive:  true,
			wantScoped:  true,
			wantAllowed: map[string]bool{"auth-x": true, "auth-a": false},
		},
		{
			name: "unbound delegate keeps inactive",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled:       true,
				DefaultPolicy: "delegate",
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"other": {AuthIDs: []string{"auth-a"}},
				},
			},
			headers:     http.Header{"Authorization": []string{"Bearer missing"}},
			wantAllowed: map[string]bool{"auth-a": true, "auth-b": true},
		},
		{
			name: "unbound deny returns auth error",
			config: internalconfig.KeyAuthRoutingConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				Bindings: map[string]internalconfig.KeyAuthBinding{
					"other": {AuthIDs: []string{"auth-a"}},
				},
			},
			headers:     http.Header{"Authorization": []string{"Bearer missing"}},
			wantActive:  true,
			wantAllowed: map[string]bool{"auth-a": true},
			wantErrCode: "auth_not_found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(&internalconfig.Config{
				Routing: internalconfig.RoutingConfig{KeyAuth: tc.config},
			})
			scope := manager.keyAuthScope(cliproxyexecutor.Options{Headers: tc.headers})
			if scope.Active() != tc.wantActive {
				t.Fatalf("Active() = %t, want %t", scope.Active(), tc.wantActive)
			}
			if scope.Scoped() != tc.wantScoped {
				t.Fatalf("Scoped() = %t, want %t", scope.Scoped(), tc.wantScoped)
			}
			if tc.wantErrCode == "" && scope.Err() != nil {
				t.Fatalf("Err() = %v, want nil", scope.Err())
			}
			if tc.wantErrCode != "" {
				var authErr *Error
				if !errors.As(scope.Err(), &authErr) || authErr.Code != tc.wantErrCode {
					t.Fatalf("Err() = %v, want code %q", scope.Err(), tc.wantErrCode)
				}
			}
			for authID, want := range tc.wantAllowed {
				if got := scope.Allow(authID); got != want {
					t.Fatalf("Allow(%q) = %t, want %t", authID, got, want)
				}
			}
		})
	}
}
