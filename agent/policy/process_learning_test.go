package policy

import (
	"testing"
	"time"

	"github.com/neuvector/neuvector/share"
)

func learningTestEngine(profile *share.CLUSProcessProfile, now *time.Time) *Engine {
	engine := &Engine{
		ProcessPolicy: map[string]*share.CLUSProcessProfile{
			"nv.test": profile,
		},
		Now: func() time.Time { return *now },
		getGroupRule: func(id string) (*share.CLUSProcessProfile, bool) {
			return nil, true
		},
	}
	return engine
}

func lookupTestProcess(t *testing.T, engine *Engine, role, name, path string, riskType string) *share.CLUSProcessProfileEntry {
	t.Helper()
	proc := &share.CLUSProcessProfileEntry{
		Name:   name,
		Path:   path,
		Action: share.PolicyActionAllow,
	}
	_, _, _, err := engine.ProcessPolicyLookup("nv.test", "container-"+role, proc, 100, ProcessLookupOption{
		Role:     role,
		RiskType: riskType,
	})
	if err != nil {
		t.Fatalf("lookup %s failed: %v", name, err)
	}
	return proc
}

func TestStartupLearningHasZeroFalsePositives(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	profile := &share.CLUSProcessProfile{
		Group:          "nv.test",
		Mode:           share.PolicyModeEnforce,
		Baseline:       share.ProfileZeroDrift,
		LearningPeriod: 10,
	}
	engine := learningTestEngine(profile, &now)

	workloads := []struct {
		role    string
		startup []struct {
			name string
			path string
		}
	}{
		{
			role: "web",
			startup: []struct{ name, path string }{
				{"nginx", "/usr/sbin/nginx"},
				{"sh", "/bin/sh"},
			},
		},
		{
			role: "cache",
			startup: []struct{ name, path string }{
				{"redis-server", "/usr/local/bin/redis-server"},
				{"sh", "/bin/sh"},
			},
		},
		{
			role: "api",
			startup: []struct{ name, path string }{
				{"node", "/usr/local/bin/node"},
				{"dumb-init", "/usr/bin/dumb-init"},
			},
		},
	}

	for _, workload := range workloads {
		engine.StartProcessLearning("container-"+workload.role, now)
		for _, app := range workload.startup {
			proc := lookupTestProcess(t, engine, workload.role, app.name, app.path, "")
			if proc.Action != share.PolicyActionLearn {
				t.Fatalf("%s/%s startup was reported as %q, want learn", workload.role, app.name, proc.Action)
			}
			if proc.Uuid == share.CLUSReservedUuidNotAllowed {
				t.Fatalf("%s/%s startup was tagged as a violation", workload.role, app.name)
			}
			if !proc.StartupLearning {
				t.Fatalf("%s/%s did not carry the startup-learning marker", workload.role, app.name)
			}
		}
	}

	now = now.Add(11 * time.Second)
	for _, workload := range workloads {
		for _, app := range workload.startup {
			proc := lookupTestProcess(t, engine, workload.role, app.name, app.path, "")
			if proc.Action != share.PolicyActionAllow {
				t.Fatalf("%s/%s baseline did not persist after learning: %q", workload.role, app.name, proc.Action)
			}
			if !proc.BaselineAllowed {
				t.Fatalf("%s/%s did not carry the baseline marker", workload.role, app.name)
			}
		}
	}

	now = now.Add(2 * time.Minute)
	proc := lookupTestProcess(t, engine, "web", "nginx", "/usr/sbin/nginx", "")
	if proc.Action == share.PolicyActionAllow {
		t.Fatal("temporary startup baseline must expire after the controller has time to persist it")
	}
}

func TestRoleScopedProcessPolicy(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	profile := &share.CLUSProcessProfile{
		Group:          "nv.test",
		Mode:           share.PolicyModeEnforce,
		Baseline:       share.ProfileZeroDrift,
		LearningPeriod: share.ProcessLearningPeriodDisable,
		Process: []*share.CLUSProcessProfileEntry{
			{Name: "agent-helper", Path: "/usr/local/bin/agent-helper", Action: share.PolicyActionAllow},
			{Name: "nginx", Path: "/usr/sbin/nginx", Role: "web", Action: share.PolicyActionAllow},
			{Name: "redis-server", Path: "/usr/local/bin/redis-server", Role: "cache", Action: share.PolicyActionAllow},
			{Name: "node", Path: "/usr/local/bin/node", Role: "api", Action: share.PolicyActionAllow},
			{Name: "sh", Path: "/bin/sh", Role: "api", Action: share.PolicyActionDeny},
		},
		Whitelist: []*share.CLUSProcessProfileEntry{
			{Name: "env", Path: "/usr/bin/env", Role: "web"},
			{Name: "date", Path: "/bin/date"},
		},
	}
	engine := learningTestEngine(profile, &now)

	cases := []struct {
		role   string
		name   string
		path   string
		action string
	}{
		{"web", "nginx", "/usr/sbin/nginx", share.PolicyActionAllow},
		{"web", "env", "/usr/bin/env", share.PolicyActionAllow},
		{"cache", "redis-server", "/usr/local/bin/redis-server", share.PolicyActionAllow},
		{"api", "node", "/usr/local/bin/node", share.PolicyActionAllow},
		{"api", "sh", "/bin/sh", share.PolicyActionDeny},
		{"web", "sh", "/bin/sh", share.PolicyActionDeny},
		{"cache", "nginx", "/usr/sbin/nginx", share.PolicyActionDeny},
		{"api", "agent-helper", "/usr/local/bin/agent-helper", share.PolicyActionAllow},
		{"cache", "date", "/bin/date", share.PolicyActionAllow},
	}

	for _, tc := range cases {
		proc := lookupTestProcess(t, engine, tc.role, tc.name, tc.path, "")
		if proc.Action != tc.action {
			t.Errorf("%s/%s action=%q, want %q", tc.role, tc.name, proc.Action, tc.action)
		}
		if proc.Role != tc.role {
			t.Errorf("%s/%s role=%q, want %q", tc.role, tc.name, proc.Role, tc.role)
		}
	}

	suspiciousProfile := &share.CLUSProcessProfile{
		Group: "nv.test",
		Process: []*share.CLUSProcessProfileEntry{
			{Name: "nc", Path: "/usr/bin/nc", Role: "web", Action: share.PolicyActionAllow},
		},
	}
	suspiciousEngine := learningTestEngine(suspiciousProfile, &now)
	if !suspiciousEngine.IsAllowedSuspiciousApp("nv.test", "web-1", "nc", "web") {
		t.Fatal("role web should allow its suspicious-app exception")
	}
	if suspiciousEngine.IsAllowedSuspiciousApp("nv.test", "api-1", "nc", "api") {
		t.Fatal("role api must not inherit role web's suspicious-app exception")
	}
}

func TestLearningDoesNotSuppressSecurityEvents(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	profile := &share.CLUSProcessProfile{
		Group:          "nv.test",
		Mode:           share.PolicyModeEnforce,
		Baseline:       share.ProfileZeroDrift,
		LearningPeriod: 30,
		Process: []*share.CLUSProcessProfileEntry{
			{Name: "sh", Path: "/bin/sh", Role: "api", Action: share.PolicyActionDeny},
		},
	}
	engine := learningTestEngine(profile, &now)
	engine.StartProcessLearning("container-api", now)

	reverseShell := lookupTestProcess(t, engine, "api", "nc", "/usr/bin/nc", "nc")
	if reverseShell.Action != share.PolicyActionDeny {
		t.Errorf("reverse-shell process was suppressed during learning: %q", reverseShell.Action)
	}
	if reverseShell.Uuid != share.CLUSReservedUuidNotAllowed {
		t.Errorf("reverse-shell process was not tagged as a violation: %q", reverseShell.Uuid)
	}

	explicitDeny := lookupTestProcess(t, engine, "api", "sh", "/bin/sh", "")
	if explicitDeny.Action != share.PolicyActionDeny {
		t.Errorf("explicit deny was suppressed during learning: %q", explicitDeny.Action)
	}

	riskyChild := &share.CLUSProcessProfileEntry{
		Name:   "bash",
		Path:   "/bin/bash",
		Action: share.PolicyActionCheckApp,
	}
	if _, _, _, err := engine.ProcessPolicyLookup("nv.test", "container-api", riskyChild, 101, ProcessLookupOption{Role: "api"}); err != nil {
		t.Fatal(err)
	}
	switch riskyChild.Action {
	case share.PolicyActionDeny, share.PolicyActionViolate, share.PolicyActionCheckApp:
	default:
		t.Errorf("risky child was suppressed during learning: %q", riskyChild.Action)
	}
}

func TestProcessLearningPeriodCompatibility(t *testing.T) {
	if got := ProcessLearningPeriod(&share.CLUSProcessProfile{}); got != time.Duration(share.ProcessLearningPeriodDefault)*time.Second {
		t.Errorf("default learning period=%v", got)
	}
	if got := ProcessLearningPeriod(&share.CLUSProcessProfile{LearningPeriod: share.ProcessLearningPeriodDisable}); got != 0 {
		t.Errorf("disabled learning period=%v", got)
	}
	if got := ProcessLearningPeriod(&share.CLUSProcessProfile{LearningPeriod: 7}); got != 7*time.Second {
		t.Errorf("configured learning period=%v", got)
	}
}
