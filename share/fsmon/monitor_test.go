package fsmon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/osutil"
)

func TestGetBaseDirPrefix(t *testing.T) {
	assert.Equal(t, "/lib64", getBaseDirPrefix(share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "ld-linux.*", Recursive: true}))
}

func TestSystemDirectoryWritesRemainMonitored(t *testing.T) {
	paths := []string{
		"/bin/evil",
		"/sbin/evil",
		"/usr/bin/evil",
		"/usr/sbin/evil",
		"/boot/evil",
		"/etc/passwd",
		"/etc/cron.d/evil",
		"/etc/init.d/evil",
		"/etc/systemd/system/evil.service",
		"/etc/ld.so.preload",
	}

	for _, path := range paths {
		matched := false
		for _, filter := range ImportantFiles {
			if filterPathMatch(path, filter) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("system path %q is no longer monitored", path)
		}
	}
}

func TestLearningModeKeepsSystemDirectoryWriteAlert(t *testing.T) {
	var reports []*MonitorMessage
	watcher := &FileWatch{
		groups: map[int]*groupInfo{
			42: {
				profile: &share.CLUSFileMonitorProfile{Group: "nv.web"},
				mode:    share.PolicyModeLearn,
				startAt: time.Now(),
			},
		},
		sendrpt: func(msg *MonitorMessage) bool {
			reports = append(reports, msg)
			return true
		},
		estRuleSrc: func(id, path string, blocked bool) string { return "nv.web" },
	}

	watcher.learnFromEvents(42, fileMod{
		finfo: &osutil.FileInfoExt{ContainerId: "web-1", Path: "/usr/bin/evil"},
	}, "/usr/bin/evil", fileEventModified)

	if len(reports) != 1 {
		t.Fatalf("system directory write reports=%d, want 1 during learning", len(reports))
	}
	if reports[0].Path != "/usr/bin/evil" {
		t.Fatalf("reported path=%q", reports[0].Path)
	}
	if reports[0].Action != share.PolicyActionViolate {
		t.Fatalf("reported action=%q, want violate", reports[0].Action)
	}
}
