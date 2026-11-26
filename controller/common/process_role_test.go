package common

import (
	"testing"

	"github.com/neuvector/neuvector/share"
)

func TestMergeProcessKeepsRoleSpecificRules(t *testing.T) {
	list := make([]*share.CLUSProcessProfileEntry, 0)
	list, changed := MergeProcess(list, &share.CLUSProcessProfileEntry{
		Name:    "sh",
		Path:    "/bin/sh",
		Role:    "web",
		Action:  share.PolicyActionAllow,
		CfgType: share.Learned,
	}, false)
	if !changed {
		t.Fatal("web rule was not inserted")
	}
	list, changed = MergeProcess(list, &share.CLUSProcessProfileEntry{
		Name:    "sh",
		Path:    "/bin/sh",
		Role:    "api",
		Action:  share.PolicyActionDeny,
		CfgType: share.UserCreated,
	}, true)
	if !changed {
		t.Fatal("api rule was not inserted")
	}
	if len(list) != 2 {
		t.Fatalf("merged rule count=%d, want 2", len(list))
	}

	for _, role := range []string{"web", "api"} {
		index, found := FindProcessInProfile(list, &share.CLUSProcessProfileEntry{
			Name: "sh",
			Path: "/bin/sh",
			Role: role,
		})
		if !found {
			t.Fatalf("role %s rule not found", role)
		}
		if list[index].Role != role {
			t.Fatalf("found role=%q, want %q", list[index].Role, role)
		}
	}
}
