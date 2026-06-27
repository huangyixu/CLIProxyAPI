package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func keyAuthOptions(clientKey string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		Headers: http.Header{"Authorization": []string{"Bearer " + clientKey}},
	}
}

func setKeyAuthConfig(manager *Manager, policy string, bindings map[string][]string) {
	cfgBindings := make(map[string]internalconfig.KeyAuthBinding, len(bindings))
	for key, authIDs := range bindings {
		cfgBindings[key] = internalconfig.KeyAuthBinding{AuthIDs: authIDs}
	}
	manager.SetConfig(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			KeyAuth: internalconfig.KeyAuthRoutingConfig{
				Enabled:       true,
				DefaultPolicy: policy,
				Bindings:      cfgBindings,
			},
		},
	})
}

func TestManagerKeyAuth_HighPriorityUnboundDoesNotBlockBoundAuth(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "high", Provider: "gemini", Attributes: map[string]string{"priority": "10"}}); errRegister != nil {
		t.Fatalf("Register(high) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "low", Provider: "gemini", Attributes: map[string]string{"priority": "0"}}); errRegister != nil {
		t.Fatalf("Register(low) error = %v", errRegister)
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"low"}})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("sk-client"), map[string]struct{}{})
	if errPick != nil {
		t.Fatalf("pickNext() error = %v", errPick)
	}
	if got == nil || got.ID != "low" {
		t.Fatalf("pickNext() auth = %#v, want low", got)
	}
}

func TestManagerKeyAuth_RoundRobinOnlyBoundAuths(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	for _, authID := range []string{"bound-a", "bound-b", "unbound"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "gemini"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", authID, errRegister)
		}
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"bound-a", "bound-b"}})

	want := []string{"bound-a", "bound-b", "bound-a"}
	for index, wantID := range want {
		got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("sk-client"), map[string]struct{}{})
		if errPick != nil {
			t.Fatalf("pickNext() #%d error = %v", index, errPick)
		}
		if got == nil || got.ID != wantID {
			t.Fatalf("pickNext() #%d auth = %#v, want %s", index, got, wantID)
		}
	}
}

func TestManagerKeyAuth_FillFirstOnlyBoundAuths(t *testing.T) {
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	for _, authID := range []string{"bound-b", "bound-a", "unbound"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "gemini"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", authID, errRegister)
		}
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"bound-a", "bound-b"}})

	for index := 0; index < 3; index++ {
		got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("sk-client"), map[string]struct{}{})
		if errPick != nil {
			t.Fatalf("pickNext() #%d error = %v", index, errPick)
		}
		if got == nil || got.ID != "bound-a" {
			t.Fatalf("pickNext() #%d auth = %#v, want bound-a", index, got)
		}
	}
}

func TestManagerKeyAuth_BoundCooldownDoesNotFallback(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID:             "bound",
		Provider:       "gemini",
		Unavailable:    true,
		NextRetryAfter: time.Now().Add(time.Minute),
		Quota:          QuotaState{Exceeded: true},
	}); errRegister != nil {
		t.Fatalf("Register(bound) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "unbound", Provider: "gemini"}); errRegister != nil {
		t.Fatalf("Register(unbound) error = %v", errRegister)
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"bound"}})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("sk-client"), map[string]struct{}{})
	if got != nil {
		t.Fatalf("pickNext() auth = %#v, want nil", got)
	}
	var cooldownErr *modelCooldownError
	if !errors.As(errPick, &cooldownErr) {
		t.Fatalf("pickNext() error = %v, want model cooldown", errPick)
	}
}

func TestManagerKeyAuth_BoundUnsupportedModelReturnsNotFound(t *testing.T) {
	model := "gemini-2.5-pro"
	registerSchedulerModels(t, "gemini", model, "unbound")

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "bound", Provider: "gemini"}); errRegister != nil {
		t.Fatalf("Register(bound) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "unbound", Provider: "gemini"}); errRegister != nil {
		t.Fatalf("Register(unbound) error = %v", errRegister)
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"bound"}})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", model, keyAuthOptions("sk-client"), map[string]struct{}{})
	if got != nil {
		t.Fatalf("pickNext() auth = %#v, want nil", got)
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr.Code != "auth_not_found" {
		t.Fatalf("pickNext() error = %v, want auth_not_found", errPick)
	}
}

func TestManagerKeyAuth_UnboundDelegateKeepsOriginalRouting(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	for _, authID := range []string{"auth-a", "auth-b"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "gemini"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", authID, errRegister)
		}
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"other": []string{"auth-b"}})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("missing"), map[string]struct{}{})
	if errPick != nil {
		t.Fatalf("pickNext() error = %v", errPick)
	}
	if got == nil || got.ID != "auth-a" {
		t.Fatalf("pickNext() auth = %#v, want auth-a", got)
	}
}

func TestManagerKeyAuth_UnboundDenyRejects(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "auth-a", Provider: "gemini"}); errRegister != nil {
		t.Fatalf("Register(auth-a) error = %v", errRegister)
	}
	setKeyAuthConfig(manager, "deny", map[string][]string{"other": []string{"auth-a"}})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("missing"), map[string]struct{}{})
	if got != nil {
		t.Fatalf("pickNext() auth = %#v, want nil", got)
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr.Code != "auth_not_found" {
		t.Fatalf("pickNext() error = %v, want auth_not_found", errPick)
	}
}

func TestManagerKeyAuth_MixedProviderOnlyBoundProviderSelected(t *testing.T) {
	model := "gpt-default"
	registerSchedulerModels(t, "gemini", model, "gemini-a")
	registerSchedulerModels(t, "claude", model, "claude-a")

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	manager.executors["claude"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "gemini-a", Provider: "gemini"}); errRegister != nil {
		t.Fatalf("Register(gemini-a) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "claude-a", Provider: "claude"}); errRegister != nil {
		t.Fatalf("Register(claude-a) error = %v", errRegister)
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"claude-a"}})

	got, _, provider, errPick := manager.pickNextMixed(context.Background(), []string{"gemini", "claude"}, model, keyAuthOptions("sk-client"), map[string]struct{}{})
	if errPick != nil {
		t.Fatalf("pickNextMixed() error = %v", errPick)
	}
	if provider != "claude" {
		t.Fatalf("pickNextMixed() provider = %q, want claude", provider)
	}
	if got == nil || got.ID != "claude-a" {
		t.Fatalf("pickNextMixed() auth = %#v, want claude-a", got)
	}
}

func TestManagerKeyAuth_PluginSchedulerReceivesScopedCandidates(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors["gemini"] = schedulerTestExecutor{}
	for _, authID := range []string{"bound", "unbound"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: "gemini"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", authID, errRegister)
		}
	}
	setKeyAuthConfig(manager, "delegate", map[string][]string{"sk-client": []string{"bound"}})

	scheduler := &fakePluginScheduler{handled: false}
	manager.SetPluginScheduler(scheduler)
	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", keyAuthOptions("sk-client"), map[string]struct{}{})
	if errPick != nil {
		t.Fatalf("pickNext() error = %v", errPick)
	}
	if got == nil || got.ID != "bound" {
		t.Fatalf("pickNext() auth = %#v, want bound", got)
	}
	if scheduler.calls != 1 {
		t.Fatalf("scheduler.calls = %d, want 1", scheduler.calls)
	}
	if len(scheduler.requests) != 1 || len(scheduler.requests[0].Candidates) != 1 || scheduler.requests[0].Candidates[0].ID != "bound" {
		t.Fatalf("scheduler candidates = %#v, want only bound", scheduler.requests)
	}
}
