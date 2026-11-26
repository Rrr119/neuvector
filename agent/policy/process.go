package policy

// #include "../../defs.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type ProcProfileBrief struct {
	name string
	path string
}

type procGrpRef struct {
	name    string
	path    string
	service string
	id      string
	role    string
	ppid    int
}

type processLearningState struct {
	start    time.Time
	baseline map[string]struct{}
}

const processBaselineRetention = time.Minute
const maxProcessBaselineEntries = 2048

// ProcessLookupOption carries runtime context that is not part of the
// persisted process rule. The zero value preserves the previous lookup
// behavior.
type ProcessLookupOption struct {
	Role     string
	RiskType string
}

// allowed parent scripts
var permitProcessGrp map[int]*procGrpRef = make(map[int]*procGrpRef)
var k8sGrpProbe utils.Set = utils.NewSet()

func (e *Engine) UpdateProcessPolicy(name string, profile *share.CLUSProcessProfile) (bool, *share.CLUSProcessProfile) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	exist, ok := e.ProcessPolicy[name]
	if !ok || !reflect.DeepEqual(exist, profile) {
		e.ProcessPolicy[name] = profile
		for _, p := range profile.Process {
			if len(p.ProbeCmds) > 0 {
				k8sGrpProbe.Add(name) // set the flag
				break
			}
		}
		return true, exist
	} else {
		return false, exist
	}
}

func (e *Engine) ObtainProcessPolicy(name, id string, roles ...string) (*share.CLUSProcessProfile, bool) {
	var role string
	if len(roles) > 0 {
		role = roles[0]
	}
	e.Mutex.Lock()
	profile := e.ProcessPolicy[name]
	e.Mutex.Unlock()
	if profile != nil { // the process policy per group has been fetched
		if role != "" {
			profile = processProfileForRole(profile, role)
		}
		if grp_profile, ok := e.getGroupRule(id); ok {
			if grp_profile == nil { // neuvector pods only
				return profile, true
			}
			if role != "" {
				grp_profile = processProfileForRole(grp_profile, role)
			}
			grp_profile.Baseline = profile.Baseline // following original profile
			if grp_profile.Mode == "" {
				grp_profile.Mode = profile.Mode // update
			} else if grp_profile.Mode != profile.Mode {
				// Detected: incomplete profile calculation, conflicts by timing
				// The new profile has not been calculated (it could be 5 seconds later) yet.
				// Just following the old group profile. it will be updated eventually.
				log.WithFields(log.Fields{"name": name, "latest-mode": profile.Mode, "group-mode": grp_profile.Mode}).Debug("GRP: ")
			}
			return grp_profile, true
		}
	}

	// log.WithFields(log.Fields{"name": name}).Debug("GRP: process profile not ready")
	return nil, false
}

func (e *Engine) processNow() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// StartProcessLearning anchors the learning window to the container start
// time when it is known to the agent.
func (e *Engine) StartProcessLearning(id string, startedAt time.Time) {
	if id == "" {
		return
	}
	if startedAt.IsZero() {
		startedAt = e.processNow()
	}

	e.Mutex.Lock()
	if e.ProcessLearning == nil {
		e.ProcessLearning = make(map[string]*processLearningState)
	}
	if state, ok := e.ProcessLearning[id]; ok {
		if state.start.After(startedAt) {
			state.start = startedAt
		}
	} else {
		e.ProcessLearning[id] = &processLearningState{
			start:    startedAt,
			baseline: make(map[string]struct{}),
		}
	}
	e.Mutex.Unlock()
}

func (e *Engine) StopProcessLearning(id string) {
	if id == "" {
		return
	}
	e.Mutex.Lock()
	delete(e.ProcessLearning, id)
	e.Mutex.Unlock()
}

func (e *Engine) processLearningActive(id string, period time.Duration) bool {
	if id == "" || period <= 0 {
		return false
	}

	now := e.processNow()
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	if e.ProcessLearning == nil {
		e.ProcessLearning = make(map[string]*processLearningState)
	}
	state, ok := e.ProcessLearning[id]
	if !ok {
		state = &processLearningState{
			start:    now,
			baseline: make(map[string]struct{}),
		}
		e.ProcessLearning[id] = state
	}
	return now.Before(state.start.Add(period))
}

func processBaselineKey(proc *share.CLUSProcessProfileEntry) string {
	return fmt.Sprintf("%s\x00%s\x00%d", proc.Name, proc.Path, proc.Uid)
}

func (e *Engine) processBaselineContains(id string, proc *share.CLUSProcessProfileEntry, period time.Duration) bool {
	if id == "" || period <= 0 {
		return false
	}
	key := processBaselineKey(proc)

	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	state, ok := e.ProcessLearning[id]
	if !ok {
		return false
	}
	if e.processNow().After(state.start.Add(period + processBaselineRetention)) {
		return false
	}
	_, ok = state.baseline[key]
	return ok
}

func (e *Engine) addProcessBaseline(id string, proc *share.CLUSProcessProfileEntry) {
	if id == "" {
		return
	}
	key := processBaselineKey(proc)

	e.Mutex.Lock()
	if e.ProcessLearning == nil {
		e.ProcessLearning = make(map[string]*processLearningState)
	}
	state, ok := e.ProcessLearning[id]
	if !ok {
		state = &processLearningState{
			start:    e.processNow(),
			baseline: make(map[string]struct{}),
		}
		e.ProcessLearning[id] = state
	}
	if len(state.baseline) < maxProcessBaselineEntries {
		state.baseline[key] = struct{}{}
	}
	e.Mutex.Unlock()
}

func (e *Engine) IsK8sGroupWithProbe(name string) bool {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	return k8sGrpProbe.Contains(name)
}

func (e *Engine) DeleteProcessPolicy(name string) {
	e.Mutex.Lock()
	delete(e.ProcessPolicy, name)
	k8sGrpProbe.Remove(name)
	log.WithFields(log.Fields{"name": name}).Debug("PROC: ")
	e.Mutex.Unlock()
}

func defaultProcessAction(mode string) string {
	switch mode {
	case share.PolicyModeLearn:
		return share.PolicyActionLearn
	case share.PolicyModeEvaluate:
		return share.PolicyActionViolate
	case share.PolicyModeEnforce:
		return share.PolicyActionDeny
	}
	return share.PolicyActionViolate
}

func MatchProfileProcess(entry *share.CLUSProcessProfileEntry, proc *share.CLUSProcessProfileEntry) bool {
	// matching the major criteria: executable path
	// all accepted:
	if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {
		return true
	}

	// application matching
	i := strings.LastIndex(proc.Path, "/")
	if i < 0 {
		log.WithFields(log.Fields{"exepath": proc.Path}).Debug("PROC: invalid path")
		return false
	}

	//
	dir := proc.Path[0:i]
	bin := proc.Path[i+1:]
	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "exepath": proc.Path, "exebin": bin, "exedir": dir}).Debug("PROC: ")
	if bin == entry.Name {
		if entry.Path == "*" || entry.Path == "" || entry.Path == "/*" {
			return true // match all
		} else if strings.HasSuffix(entry.Path, "/*") && entry.Name != "*" { // recursive match
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		}
	}

	// wildcard name
	if entry.Name == "*" {
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		} else if len(entry.ProbeCmds) > 0 { // probe shell commands
			return bin == entry.Path
		} else { // on a spefific file
			return proc.Path == entry.Path
		}
	} else { // recursive directory ( *, /bin/*, and /usr/*/nginx)
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			return strings.HasPrefix(dir, path) && (entry.Name == proc.Name)
		} else if index := strings.Index(entry.Path, "/*/"); index > -1 {
			return strings.HasPrefix(dir, entry.Path[:index]) && (entry.Name == proc.Name) && (bin == filepath.Base(entry.Path))
		}
	}

	// regular cases
	if entry.Path != "" && entry.Path != "*" && entry.Path != "/*" {
		if proc.Path != entry.Path {
			return false
		}
	}

	// cases for busybox and others
	if proc.Name != entry.Name {
		return false
	}

	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "execPath": proc.Path, "execnName": proc.Name}).Debug("PROC: matched")
	return true
}

func processRoleMatches(entryRole, role string) bool {
	if entryRole == "" {
		return true
	}
	if role == "" {
		return false
	}
	if entryRole == "*" {
		return true
	}
	return strings.EqualFold(entryRole, role)
}

// ProcessRuleMatchesRole reports whether a persisted rule applies to a
// workload role. An empty rule role is shared by all roles.
func ProcessRuleMatchesRole(entry *share.CLUSProcessProfileEntry, role string) bool {
	if entry == nil {
		return false
	}
	return processRoleMatches(entry.Role, role)
}

// MatchProfileProcessForRole applies the existing rule matcher after checking
// the rule's workload role scope.
func MatchProfileProcessForRole(entry *share.CLUSProcessProfileEntry, proc *share.CLUSProcessProfileEntry, role string) bool {
	if !processRoleMatches(entry.Role, role) {
		return false
	}
	return MatchProfileProcess(entry, proc)
}

func cloneProcessEntry(entry *share.CLUSProcessProfileEntry) *share.CLUSProcessProfileEntry {
	if entry == nil {
		return nil
	}
	copy := *entry
	if entry.Hash != nil {
		copy.Hash = append([]byte(nil), entry.Hash...)
	}
	if entry.ProbeCmds != nil {
		copy.ProbeCmds = append([]string(nil), entry.ProbeCmds...)
	}
	return &copy
}

// mergeProcessProfileEntries keeps the existing rule-engine priority order:
// deny rules are evaluated before allow rules, with wildcard allow-all kept as
// the explicit override used by the current API.
func mergeProcessProfileEntries(entries []*share.CLUSProcessProfileEntry) []*share.CLUSProcessProfileEntry {
	buckets := make([]map[string]*share.CLUSProcessProfileEntry, 7)
	for i := range buckets {
		buckets[i] = make(map[string]*share.CLUSProcessProfileEntry)
	}

	for _, entry := range entries {
		if entry == nil {
			continue
		}
		key := fmt.Sprintf("%s:%s:%s", entry.Role, entry.Name, entry.Path)
		if entry.Action == share.PolicyActionDeny {
			switch {
			case entry.Name == "*" && entry.Path == "*":
				// deny-all is rejected by the API; preserve the existing behavior.
			case entry.Name == "*":
				buckets[3][key] = entry
			case strings.HasSuffix(entry.Path, "/*"):
				buckets[2][key] = entry
			default:
				buckets[1][key] = entry
			}
		} else {
			switch {
			case entry.Name == "*" && entry.Path == "*":
				buckets[0][key] = entry
			case entry.Name == "*":
				buckets[6][key] = entry
			case strings.HasSuffix(entry.Path, "/*"):
				buckets[5][key] = entry
			default:
				buckets[4][key] = entry
			}
		}
	}

	list := make([]*share.CLUSProcessProfileEntry, 0, len(entries))
	for _, bucket := range buckets {
		bucketList := make([]*share.CLUSProcessProfileEntry, 0, len(bucket))
		for _, entry := range bucket {
			bucketList = append(bucketList, entry)
		}
		sort.Slice(bucketList, func(i, j int) bool {
			if bucketList[i].Name == bucketList[j].Name {
				return bucketList[i].Path < bucketList[j].Path
			}
			return bucketList[i].Name < bucketList[j].Name
		})
		list = append(list, bucketList...)
	}
	return list
}

func processProfileForRole(profile *share.CLUSProcessProfile, role string) *share.CLUSProcessProfile {
	if profile == nil {
		return nil
	}

	needsRoleMerge := len(profile.Whitelist) > 0
	if !needsRoleMerge {
		for _, entry := range profile.Process {
			if entry.Role != "" {
				needsRoleMerge = true
				break
			}
		}
	}
	if !needsRoleMerge {
		return profile
	}

	effective := *profile
	entries := make([]*share.CLUSProcessProfileEntry, 0, len(profile.Process)+len(profile.Whitelist))
	for _, entry := range profile.Process {
		if processRoleMatches(entry.Role, role) {
			entries = append(entries, entry)
		}
	}
	for _, entry := range profile.Whitelist {
		if !processRoleMatches(entry.Role, role) {
			continue
		}
		allow := cloneProcessEntry(entry)
		allow.Action = share.PolicyActionAllow
		if allow.CfgType == 0 {
			allow.CfgType = share.UserCreated
		}
		entries = append(entries, allow)
	}
	effective.Process = mergeProcessProfileEntries(entries)
	return &effective
}

// ProcessLearningPeriod returns the configured startup learning window.
// Zero keeps the backward-compatible default; a negative value disables it.
func ProcessLearningPeriod(profile *share.CLUSProcessProfile) time.Duration {
	if profile == nil {
		return 0
	}
	period := profile.LearningPeriod
	if period == 0 {
		period = share.ProcessLearningPeriodDefault
	}
	if period < 0 {
		return 0
	}
	return time.Duration(period) * time.Second
}

func shouldLearnDuringStartup(proc *share.CLUSProcessProfileEntry, riskType string) bool {
	if riskType != "" {
		return false
	}
	switch proc.Action {
	case share.PolicyActionDeny, share.PolicyActionViolate, share.PolicyActionCheckApp:
		return false
	}
	return true
}

func (e *Engine) ProcessPolicyLookup(name, id string, proc *share.CLUSProcessProfileEntry, pid int, options ...ProcessLookupOption) (string, string, string, error) {
	group := name // service group
	var option ProcessLookupOption
	if len(options) > 0 {
		option = options[0]
	}
	profile, ok := e.ObtainProcessPolicy(name, id)
	if ok {
		profile = processProfileForRole(profile, option.Role)
		if option.Role != "" {
			proc.Role = option.Role
		}
		learning := false
		if shouldLearnDuringStartup(proc, option.RiskType) {
			learning = e.processLearningActive(id, ProcessLearningPeriod(profile))
		}
		baselineHit := false
		if shouldLearnDuringStartup(proc, option.RiskType) {
			baselineHit = e.processBaselineContains(id, proc, ProcessLearningPeriod(profile))
		}

		var matchedEntry *share.CLUSProcessProfileEntry
		for _, p := range profile.Process {
			if profile.Mode == share.PolicyModeLearn && len(p.ProbeCmds) > 0 {
				//	if p.Name == "sh" && p.Path == "*" {		// replace
				//		if ok, app, _ := global.SYS.DefaultShellCmd(pid, "sh"); ok {
				//			p.Name = "*"
				//			p.Path = app
				//		}
				//	}
				continue // trigger a learning event
			}

			if MatchProfileProcessForRole(p, proc, option.Role) {
				matchedEntry = p
				proc.Action = p.Action
				proc.AllowFileUpdate = p.AllowFileUpdate
				proc.ProbeCmds = p.ProbeCmds
				proc.CfgType = p.CfgType
				break
			}
		}

		if matchedEntry != nil {
			proc.Uuid = matchedEntry.Uuid
			if matchedEntry.DerivedGroup != "" { // "" : internal reference for service group
				group = matchedEntry.DerivedGroup
			}
			if proc.Action == share.PolicyActionAllow {
				if profile.HashEnable {
					hash, err := global.SYS.GetFileHash(pid, proc.Path)
					if err != nil {
						// Don't log if file doesn't exist - process may have exited or path inaccessible
						if !errors.Is(err, os.ErrNotExist) {
							log.WithError(err).WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: failed to get file hash")
						}
					} else if hash != nil {
						if len(matchedEntry.Hash) == 0 {
							log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: update hash")
							matchedEntry.Hash = hash
							proc.Action = share.PolicyActionLearn
						} else if string(matchedEntry.Hash) != string(hash) {
							log.WithFields(log.Fields{"group": name, "path": proc.Path, "rec": matchedEntry.Hash, "hash": hash}).Debug("PROC: mismatched hash")
							proc.Action = share.PolicyActionViolate
						}
					} else {
						log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: hash failed")
					}
				}

				// discovery mode and from a group rule
				// after re-calculated at group_profile, the service rules(updated at last) will become its derived_group ""
				// log.WithFields(log.Fields{"mode": profile.Mode, "name": name, "proc": proc, "group": group}).Debug("PROC: ")
				if profile.Mode == share.PolicyModeLearn && group != name {
					e.Mutex.Lock()
					prf := e.ProcessPolicy[name]
					e.Mutex.Unlock()
					found := false
					if prf != nil {
						for _, p := range prf.Process {
							if MatchProfileProcessForRole(p, proc, option.Role) {
								found = true
								break
							}
						}
					}

					if !found {
						//	log.WithFields(log.Fields{"name": name, "proc": proc}).Debug("PROC: learnt")
						proc.Action = share.PolicyActionLearn
					}
				}
			} else { // deny decision
				// update deny decision in two other modes
				if profile.Mode != share.PolicyModeEnforce {
					proc.Action = share.PolicyActionViolate
				}
			}
		} else {
			switch {
			case baselineHit:
				proc.Action = share.PolicyActionAllow
				proc.Uuid = ""
				proc.BaselineAllowed = true
				proc.CfgType = share.UserCreated
			case learning:
				// The startup baseline is learned without producing an incident.
				// Explicit deny rules and suspicious processes bypass this path.
				proc.Action = share.PolicyActionLearn
				proc.Uuid = ""
				proc.StartupLearning = true
				e.addProcessBaseline(id, proc)
			case profile.Baseline == share.ProfileBasic || !e.IsK8sGroupWithProbe(name):
				//not found in profile
				act := defaultProcessAction(profile.Mode)
				proc.Action = act
				proc.Uuid = share.CLUSReservedUuidNotAllowed
				if act == share.PolicyActionLearn {
					e.addProcessBaseline(id, proc)
				}
			}
		}
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("")
	} else {
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("Profile not found")
		return "", "", "", errors.New("Profile not found")
	}
	return profile.Mode, profile.Baseline, group, nil
}

// matching the process name: suspicious process is defined by name only
func (e *Engine) IsAllowedSuspiciousApp(service, id, name string, roles ...string) bool {
	var role string
	if len(roles) > 0 {
		role = roles[0]
	}
	profile, ok := e.ObtainProcessPolicy(service, id)
	if ok {
		for _, entry := range profile.Process {
			if !processRoleMatches(entry.Role, role) {
				continue
			}
			// all accepted:
			if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {
				return true
			}

			if name == entry.Name {
				return true
			}
		}
	}
	return false
}

// allowed by parent process name
// The program logic is located at faccess_linux.go: isAllowedByParentApp()
func (e *Engine) IsAllowedByParentApp(service, id, name, pname, ppath string, pgid int, roles ...string) bool {
	var allowed bool
	var role string
	if len(roles) > 0 {
		role = roles[0]
	}

	profile, ok := e.ObtainProcessPolicy(service, id)
	if ok {
		if procGrp, ok := permitProcessGrp[pgid]; ok {
			ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
			// log.WithFields(log.Fields{"pgid": pgid, "ppid": ppid, "procGrp": procGrp}).Debug("exist")
			if procGrp.id != id || procGrp.role != role || ppid != procGrp.ppid {
				// invalid match, reset record
				delete(permitProcessGrp, pgid)
				procGrp = nil
			} else {
				return true
			}
		}

		for _, entry := range profile.Process {
			if !processRoleMatches(entry.Role, role) {
				continue
			}
			if entry.Action == share.PolicyActionAllow && strings.HasSuffix(entry.Name, "/*") {
				n := strings.TrimSuffix(entry.Name, "/*")
				if pname == n || name == n { // allowed parent name (including itself)
					if entry.Path == "" || entry.Path == "*" || entry.Path == "/*" {
						allowed = true
					}

					if !allowed && strings.HasSuffix(entry.Path, "/*") {
						p := strings.TrimSuffix(entry.Path, "/*")
						allowed = strings.HasPrefix(ppath, p)
					}

					if !allowed {
						allowed = entry.Path == ppath
					}
				}

				if allowed {
					ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
					tagRef := &procGrpRef{name: n, path: entry.Path, service: service, id: id, role: role, ppid: ppid}
					permitProcessGrp[pgid] = tagRef
					log.WithFields(log.Fields{"pgid": pgid, "ppath": ppath, "tagRef": tagRef}).Debug()
					break
				}
			}
		}
	}
	return allowed
}

// ///////////////////////////////////////////////////////////////////
func buildCustomizedProfile(serviceGroup, mode string, whtLst, blackLst []ProcProfileBrief) *share.CLUSProcessProfile {
	profile := &share.CLUSProcessProfile{
		Group:        serviceGroup,
		Baseline:     share.ProfileZeroDrift,
		AlertDisable: false,
		HashEnable:   false,
		Mode:         mode,
	}

	// white list
	for _, ppw := range whtLst {
		wht := &share.CLUSProcessProfileEntry{
			Name:      ppw.name,
			Path:      ppw.path,
			Action:    share.PolicyActionAllow, // white list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, wht)
	}

	// black list
	for _, ppb := range blackLst {
		blk := &share.CLUSProcessProfileEntry{
			Name:      ppb.name,
			Path:      ppb.path,
			Action:    share.PolicyActionDeny, // black list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, blk)
	}
	return profile
}

// ///////////////////////////////////////////////////////////////////
func (e *Engine) InsertNeuvectorProcessProfilePolicy(group, role string) {
	profile := &share.CLUSProcessProfile{
		Group:        group,
		Baseline:     share.ProfileZeroDrift,
		AlertDisable: false,
		HashEnable:   false,
		Mode:         share.PolicyModeEnforce,
	}
	e.UpdateProcessPolicy(group, profile)
}
