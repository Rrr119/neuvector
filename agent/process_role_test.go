package main

import "testing"

func TestProcessRoleSelection(t *testing.T) {
	cases := []struct {
		name    string
		labels  map[string]string
		service string
		want    string
	}{
		{
			name:    "explicit neuvector role",
			labels:  map[string]string{"neuvector.role": "api", "app": "ignored"},
			service: "checkout.default",
			want:    "api",
		},
		{
			name:    "kubernetes component",
			labels:  map[string]string{"app.kubernetes.io/component": "worker"},
			service: "jobs.default",
			want:    "worker",
		},
		{
			name:    "docker compose service",
			labels:  map[string]string{"com.docker.compose.service": "cache"},
			service: "cache",
			want:    "cache",
		},
		{
			name:    "service fallback",
			labels:  nil,
			service: "frontend.production",
			want:    "frontend",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := processRole(tc.labels, tc.service); got != tc.want {
				t.Fatalf("processRole()=%q, want %q", got, tc.want)
			}
		})
	}
}
