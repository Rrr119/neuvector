package share

import (
	"testing"

	"github.com/golang/protobuf/proto"
)

func TestProcProfileRequestCarriesRole(t *testing.T) {
	input := &CLUSProcProfileReq{
		GroupName: CLUSProcessRoleGroupName("nv.api", "api"),
		Name:      "node",
		Path:      "/usr/local/bin/node",
		Action:    PolicyActionLearn,
	}

	data, err := proto.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	var output CLUSProcProfileReq
	if err := proto.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	group, role := CLUSProcessRoleGroupSplit(output.GroupName)
	if group != "nv.api" || role != "api" {
		t.Fatalf("group=%q role=%q", group, role)
	}
}
