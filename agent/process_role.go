package main

import (
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

var processRoleLabels = []string{
	share.NeuVectorLabelRole,
	"app.kubernetes.io/component",
	"app.kubernetes.io/name",
	"k8s-app",
	"component",
	"app",
	"role",
	container.DockerComposeServiceKey,
}

// processRole returns a stable role key for role-scoped process rules. An
// explicit label wins; otherwise common Kubernetes/Docker workload labels are
// used, and finally the service name before its domain suffix.
func processRole(labels map[string]string, service string) string {
	for _, key := range processRoleLabels {
		if role := strings.TrimSpace(labels[key]); role != "" {
			return role
		}
	}

	service = strings.TrimSpace(service)
	if index := strings.IndexByte(service, '.'); index > 0 {
		service = service[:index]
	}
	if index := strings.LastIndexByte(service, '/'); index >= 0 {
		service = service[index+1:]
	}
	return service
}

func containerProcessRole(id string) string {
	if id == "" {
		return ""
	}
	if c, ok := gInfoReadActiveContainer(id); ok {
		if c.info != nil {
			return processRole(c.info.Labels, c.service)
		}
		return processRole(nil, c.service)
	}
	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		if c.info != nil {
			return processRole(c.info.Labels, c.service)
		}
		return processRole(nil, c.service)
	}
	return ""
}
