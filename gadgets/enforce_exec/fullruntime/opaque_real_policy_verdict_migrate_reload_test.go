// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// G025 steps 7 (route movement) and 8 (publication/reload) of the attached
// verdict diagnostic. Synthetic test authority only; never product Ready.

// opaqueMigration is the second disposable cgroup (route slot 1, scope 11,
// opposite class) and the shebang fixture whose interpreter exec-open the
// helper holds with FAN_OPEN_EXEC_PERM.
type opaqueMigration struct {
	path, script, interp string
	ino                  uint64
}

func newOpaqueMigration(t *testing.T, cgroup string) opaqueMigration {
	t.Helper()
	var m opaqueMigration
	dir, err := os.MkdirTemp(filepath.Dir(cgroup), "ig15-g005-reallive-migrate-")
	if err != nil {
		t.Fatalf("second route cgroup: %v", err)
	}
	// Runs after the helper (and every migrated child) was reaped.
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil || st.Ino == 0 {
		t.Fatalf("second route cgroup %s: %v", dir, err)
	}
	m.path, m.ino = dir, st.Ino
	work := t.TempDir()
	bash, err := os.ReadFile("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	m.interp = filepath.Join(work, "interp")
	if err := os.WriteFile(m.interp, bash, 0o755); err != nil {
		t.Fatal(err)
	}
	// The interpreter's own fresh exec is the first exec after migration.
	m.script = filepath.Join(work, "script")
	if err := os.WriteFile(m.script, []byte("#!"+m.interp+"\nexec /bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// Capsule statistics (full/shared_exec_capsule.h SE_CAP_STAT_*).
const (
	opaqueCapBegin          = 0
	opaqueCapStaleRetired   = 2
	opaqueCapFrozen         = 3
	opaqueCapFrozenUncover  = 4
	opaqueCapPinned         = 5
	opaqueCapPinFailed      = 6
	opaqueCapOriginalClaim  = 7
	opaqueCapTerminal       = 8
	opaqueCapForeignTerm    = 9
	opaqueCapSuccess        = 10
	opaqueCapReleaseFault   = 12
	opaqueCapFault          = 13
	opaqueCapStats          = 15
	opaqueRouteClassOffset  = 56
	opaqueRoutePhaseOffset  = 60
	opaqueRouteEarlyOffset  = 64
	opaqueRoutePinsOffset   = 96
	opaqueRouteLatchOffset  = 100
	opaqueRouteAnchorLength = 104
)

func (v *opaqueVerdictRun) capsuleStats() [opaqueCapStats]uint64 {
	v.t.Helper()
	raw, err := v.c.Maps["se_exec_capsule_stats"].LookupBytes(uint32(0))
	if err != nil || len(raw) != 8*opaqueCapStats {
		v.t.Fatalf("capsule stats: len=%d err=%v", len(raw), err)
	}
	var out [opaqueCapStats]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return out
}

// routeBalanced fails unless every route has no early claim, source pin or
// unresolved-source latch: no in-flight admission survived its exec.
func (v *opaqueVerdictRun) routeBalanced(label string) {
	v.t.Helper()
	for slot := uint32(0); slot < v.spec.Maps["se_routes"].MaxEntries; slot++ {
		route, err := v.c.Maps["se_routes"].LookupBytes(slot)
		if err != nil || len(route) != opaqueRouteAnchorLength {
			v.t.Fatalf("%s: route %d: len=%d err=%v", label, slot, len(route), err)
		}
		early := binary.LittleEndian.Uint32(route[opaqueRouteEarlyOffset:])
		pins := binary.LittleEndian.Uint32(route[opaqueRoutePinsOffset:])
		latch := binary.LittleEndian.Uint32(route[opaqueRouteLatchOffset:])
		if early|pins|latch != 0 {
			v.t.Fatalf("%s: route %d unbalanced: early=%d pins=%d unresolved=%d", label, slot, early, pins, latch)
		}
	}
}

// settleAny waits for the final free of the n non-parent TASKs (DEAD, receipt
// retired) and returns their exact refunds. Unlike settleTasks it accepts a
// quarantined child: a migrated exec may legitimately fail closed.
func (v *opaqueVerdictRun) settleAny(label string, n int) (refunds []opaqueVerdictRefund, flags []uint64) {
	v.t.Helper()
	children := v.childTasks(label)
	if len(children) != n {
		v.t.Fatalf("%s: expected %d child TASKs, got %d", label, n, len(children))
	}
	for _, entry := range children {
		child, locator, slot := entry.physical, entry.locator, entry.slot
		v.finalFree(label, entry)
		taskFlags, cookie, settled := v.task(child, locator)
		if !settled {
			v.t.Fatalf("%s: child reader/exec still owned after final free (flags=%d)", label, taskFlags)
		}
		if old, ok := v.seen[child]; ok {
			v.reuses++
			if cookie <= old {
				v.t.Fatalf("%s: physical reuse kept stale identity", label)
			}
		}
		v.seen[child] = cookie
		refunds = append(refunds, opaqueVerdictRefund{slot, cookie})
		flags = append(flags, taskFlags)
	}
	return refunds, flags
}

// migrate runs the three G025 step-7 movements of one child each from the
// seeded route A (v.class) to route B (3 - v.class), then a control child
// on A. Product semantics under test: the class of a physical exec is frozen
// at its first selected admission (full/shared_exec_capsule.h); a TASK's
// scope is immutable, so movement never relabels its history (struct
// se_task_state in full/shared_exec.h): a fresh exec on B is admitted with
// B's class but fails closed in that class (Strict denies, Audit runs
// unevaluated).
func (v *opaqueVerdictRun) migrate(m opaqueMigration) {
	v.t.Helper()
	other := 3 - v.class
	route, err := v.c.Maps["se_routes"].LookupBytes(uint32(1))
	if err != nil || len(route) != opaqueRouteAnchorLength ||
		binary.LittleEndian.Uint32(route[opaqueRouteClassOffset:]) != uint32(other) ||
		binary.LittleEndian.Uint32(route[opaqueRoutePhaseOffset:]) != 2 {
		v.t.Fatalf("second route is not an ACTIVE class-%d route: %v", other, err)
	}
	freshExit := map[int]int{1: 0, 2: 77}[other]
	// Each scenario is a subtest so a failure still runs the others; the
	// parent test fails if any did.
	parent := v.t
	failed := false
	for _, s := range []struct{ label, command string }{
		{"migration mid-birth (clone3 CLONE_INTO_CGROUP)", "MIGRATEB\n"},
		{"migration between fork and exec", "MIGRATEF\n"},
		{"migration mid-exec (FAN_OPEN_EXEC_PERM hold)", "MIGRATEX\n"},
	} {
		if !parent.Run(s.label, func(t *testing.T) {
			v.t = t
			defer func() { v.t = parent }()
			v.migratedChild(s.label, s.command, freshExit)
		}) {
			failed = true
		}
	}
	if failed {
		v.t.Fatal("route movement: at least one migration scenario failed (see subtests)")
	}
	v.child("euid 0 on the original route after migrations", "FORK\n", 0, true)
	v.t.Logf("route movement: original class %d honoured in flight, fresh execs on class-%d route fail closed in that class, pins balanced, no current-route fallback, exact refunds", v.class, other)
}

// migratedChild runs one migration scenario and checks it exactly.
//   - MIGRATEB: clone3(CLONE_INTO_CGROUP) places the child in a cgroup the
//     source cannot see at security_task_alloc, so the source refuses the
//     birth in the parent route's class before any charge
//     (real_owner_child_prepare_claimed, bpf.c clone_flags bit 33): Strict
//     A fails the fork with EPERM; Audit A leaves the child unconstructed
//     (no TASK, no WORK) and its exec on B (Strict) is admitted and pinned
//     on B and denied for want of a TASK (77).
//   - MIGRATEF: the only exec is a fresh exec on B. It is admitted
//     and pinned on B (class B), never evaluated (TASK scope A), and exits by
//     B's class: freshExit.
//   - MIGRATEX: the script's admission on A is evaluated under A (the euid-0
//     rule matches: an allow with mode A). The interpreter admission of the
//     same exec, after the move, is an ORIGINAL claim on A: with A Strict it
//     is refused (EPERM, the pending receipt is quarantined), with A Audit it
//     stays nonblocking. Then one fresh exec runs on B: with A Strict the
//     child's own /bin/true (B Audit: exit 0), with A Audit the
//     interpreter's "exec /bin/true" (B Strict: bash exits 126).
func (v *opaqueVerdictRun) migratedChild(label, command string, freshExit int) {
	v.t.Helper()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeCap := v.capsuleStats()
	baseTasks, baseWorks := v.accounts(label)
	v.lastDeny = -1
	if _, err := v.stdin.Write([]byte(command)); err != nil {
		v.t.Fatal(err)
	}
	line, err := v.stdout.ReadString('\n')
	if err != nil {
		v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
	}
	midExec := command == "MIGRATEX\n"
	midBirth := command == "MIGRATEB\n"
	beforeBirths := v.birthOutcomes(label)
	var exit, scriptErrno int
	refused := false
	if midExec {
		var pid, held int
		if n, _ := fmt.Sscanf(line, "MIGRATED:%d:%d:%d:%d\n", &pid, &held, &scriptErrno, &exit); n != 4 || pid <= 0 || held != 1 {
			v.t.Fatalf("%s: line=%q: the interpreter exec-open was not held and migrated", label, line)
		}
	} else {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 3 || fields[0] != "FORKED" {
			v.t.Fatalf("%s: line=%q stderr=%q", label, line, v.stderr.String())
		}
		if exit, err = strconv.Atoi(fields[2]); err != nil {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		// Only a Strict mid-birth source refusal may fail the fork,
		// and only with EPERM.
		if refused = fields[1] == "-1"; refused && (!midBirth || v.class != 2 || exit != int(unix.EPERM)) {
			v.t.Fatalf("%s: fork refused: line=%q (class %d)", label, line, v.class)
		}
	}
	children := 1
	if midBirth {
		children = 0 // never constructed
	}
	refunds, flags := v.settleAny(label, children)
	works := v.settleRound(label, -1)
	evals, matches := v.progress()
	afterCap := v.capsuleStats()
	var capDelta [opaqueCapStats]uint64
	for i := range capDelta {
		capDelta[i] = afterCap[i] - beforeCap[i]
	}
	var outcomes [4]uint64
	afterOutcomes := v.terminalOutcomes()
	for i := range outcomes {
		outcomes[i] = afterOutcomes[i] - beforeOutcomes[i]
		v.outcomes[i] += outcomes[i]
	}
	v.t.Logf("%s: exit=%d script errno=%d; evaluations %d matches %d; capsule delta begin=%d frozen=%d pinned=%d original_claim=%d terminal=%d success=%d fault=%d; terminal outcome deltas %v; %d WORKs; child flags %v",
		label, exit, scriptErrno, evals-beforeEvals, matches-beforeMatches,
		capDelta[opaqueCapBegin], capDelta[opaqueCapFrozen], capDelta[opaqueCapPinned],
		capDelta[opaqueCapOriginalClaim], capDelta[opaqueCapTerminal], capDelta[opaqueCapSuccess],
		capDelta[opaqueCapFault], outcomes, works, flags)
	// No current-route fallback: se_cap_degrade is the only path that
	// admits through the current cgroup after a capsule failure, and it
	// always counts FAULT. Every admission was covered (no uncovered
	// freeze, no stale capsule) and every pin was taken and released.
	if capDelta[opaqueCapFault] != 0 || capDelta[opaqueCapReleaseFault] != 0 ||
		capDelta[opaqueCapPinFailed] != 0 || capDelta[opaqueCapFrozenUncover] != 0 ||
		capDelta[opaqueCapStaleRetired] != 0 || capDelta[opaqueCapForeignTerm] != 0 {
		v.t.Fatalf("%s: capsule fault/fallback deltas %v", label, capDelta)
	}
	afterBirths := v.birthOutcomes(label)
	if midBirth {
		// Exact source refusal before any WORK charge or constructor
		// attempt: every birth accounting witness is unchanged.
		if afterBirths != beforeBirths {
			v.t.Fatalf("%s: birth outcomes %v -> %v, want an uncharged source refusal", label, beforeBirths, afterBirths)
		}
		if v.class == 2 {
			if !refused || capDelta != [opaqueCapStats]uint64{} {
				v.t.Fatalf("%s: Strict mid-birth: refused=%v capsule delta %v, want EPERM and no exec", label, refused, capDelta)
			}
		} else {
			// Unconstructed child, born on B (Strict): its exec is
			// admitted and pinned on B, then denied without a TASK.
			want := [opaqueCapStats]uint64{}
			want[opaqueCapBegin], want[opaqueCapFrozen], want[opaqueCapPinned], want[opaqueCapTerminal] = 1, 1, 1, 1
			if refused || exit != 77 || capDelta != want {
				v.t.Fatalf("%s: Audit mid-birth: exit %d capsule delta %v, want unconstructed child denied on the Strict route (77, %v)", label, exit, capDelta, want)
			}
		}
		if evals != beforeEvals || matches != beforeMatches || v.windows() != beforeWindows ||
			v.lastDeny != -1 || outcomes != [4]uint64{} || works != 0 {
			v.t.Fatalf("%s: refused birth was charged or evaluated (evals %d->%d, decision %d, outcomes %v, %d WORKs)",
				label, beforeEvals, evals, v.lastDeny, outcomes, works)
		}
	} else if midExec {
		// Original class honoured in flight: the interpreter admission
		// was an ORIGINAL claim with class A, decided by A, not by B.
		wantErrno, wantExit := 0, 126
		if v.class == 2 {
			wantErrno, wantExit = int(unix.EPERM), 0
		}
		if scriptErrno != wantErrno || exit != wantExit {
			v.t.Fatalf("%s: script errno %d exit %d, want errno %d exit %d for original class %d", label, scriptErrno, exit, wantErrno, wantExit, v.class)
		}
		want := map[int]uint64{
			opaqueCapBegin: 2, opaqueCapFrozen: 2, opaqueCapPinned: 2,
			opaqueCapOriginalClaim: 1, opaqueCapTerminal: 2, opaqueCapSuccess: 1,
		}
		for i, n := range want {
			if capDelta[i] != n {
				v.t.Fatalf("%s: capsule stat %d delta %d, want %d (%v)", label, i, capDelta[i], n, capDelta)
			}
		}
		// Only the script's admission on A was evaluated, by the matching
		// rule: the verdict witness is an allow with A's mode.
		if evals != beforeEvals+1 || matches != beforeMatches+1 || v.lastDeny != v.class {
			v.t.Fatalf("%s: evaluations %d->%d matches %d->%d decision %d, want one matching allow with mode %d",
				label, beforeEvals, evals, beforeMatches, matches, v.lastDeny, v.class)
		}
		if windows := v.windows() - beforeWindows; windows != uint64((v.rules+15)/16-1) {
			v.t.Fatalf("%s: rule windows %d for one evaluation of %d rules", label, windows, v.rules)
		}
		// Birth + evaluation WORK, plus any transient terminal WORK the
		// witness counted (FALLBACK_CHARGED), each refunded exactly.
		if want := 2 + int(outcomes[2]); works != want {
			v.t.Fatalf("%s: reaped %d WORKs, want birth + evaluation + %d transient = %d", label, works, outcomes[2], want)
		}
		if outcomes[0]+outcomes[1]+outcomes[2]+outcomes[3] == 0 {
			v.t.Fatalf("%s: the evaluated receipt produced no terminal outcome", label)
		}
	} else {
		if exit != freshExit {
			v.t.Fatalf("%s: exit %d, want %d (fresh exec on the class-%d route)", label, exit, freshExit, 3-v.class)
		}
		want := map[int]uint64{
			opaqueCapBegin: 1, opaqueCapFrozen: 1, opaqueCapPinned: 1,
			opaqueCapOriginalClaim: 0, opaqueCapTerminal: 1, opaqueCapSuccess: uint64(map[bool]int{true: 1}[exit == 0]),
		}
		for i, n := range want {
			if capDelta[i] != n {
				v.t.Fatalf("%s: capsule stat %d delta %d, want %d (%v)", label, i, capDelta[i], n, capDelta)
			}
		}
		// The TASK's immutable scope (A) never evaluates under B.
		if evals != beforeEvals || matches != beforeMatches || v.windows() != beforeWindows ||
			v.lastDeny != -1 || outcomes != [4]uint64{} {
			v.t.Fatalf("%s: a moved child was evaluated (%d->%d, decision %d, outcomes %v)", label, beforeEvals, evals, v.lastDeny, outcomes)
		}
		if works != 1 {
			v.t.Fatalf("%s: reaped %d WORKs, want exactly the birth WORK", label, works)
		}
	}
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.routeBalanced(label)
	v.parentQualified(label)
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
}

// opaqueEvaluation is one reaped evaluation WORK: the generation frozen at
// its admission (view header) and its decision.
type opaqueEvaluation struct {
	generation, deny, mode, matched uint64
}

// reapRecorded reaps every non-parent WORK like settleRound and returns the
// count and each evaluation WORK's frozen generation and decision.
func (v *opaqueVerdictRun) reapRecorded() (works int, evals []opaqueEvaluation) {
	v.t.Helper()
	for slot := uint32(0); slot < v.spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
		cookie := v.charge("se_opaque_work_charges", slot)
		if cookie == 0 {
			continue
		}
		if saved, ok := v.parentWorks[slot]; ok && saved == cookie {
			continue
		}
		works++
		if raw, err := v.c.Maps["se_opaque_work_payload"].LookupBytes(slot); err == nil && len(raw) > 0 {
			if mode := v.field(v.invocationType, raw, "observation", "evaluator", "decision", "mode"); mode != 0 {
				evals = append(evals, opaqueEvaluation{
					generation: v.field(v.invocationType, raw, "view", "header", "generation"),
					deny:       v.field(v.invocationType, raw, "observation", "evaluator", "decision", "deny"),
					mode:       mode,
					matched:    v.field(v.invocationType, raw, "observation", "evaluator", "decision", "matched_rules"),
				})
			}
		}
		v.reap("work", slot, cookie)
	}
	return works, evals
}

// opaqueBinding is the first binding's published snapshot tuple.
type opaqueBinding struct {
	generation, activeSerial, activeRecord uint64
	phases                                 [2]uint64
	pins                                   [2]uint64
}

func (v *opaqueVerdictRun) binding() opaqueBinding {
	v.t.Helper()
	var bindingType, objectType *btf.Struct
	if err := v.spec.Types.TypeByName("se_shared_binding", &bindingType); err != nil {
		v.t.Fatal(err)
	}
	if err := v.spec.Types.TypeByName("se_shared_object", &objectType); err != nil {
		v.t.Fatal(err)
	}
	raw, err := v.c.Maps["se_bindings"].LookupBytes(uint32(0))
	if err != nil {
		v.t.Fatal(err)
	}
	b := opaqueBinding{
		generation:   v.field(bindingType, raw, "state", "generation"),
		activeSerial: v.field(bindingType, raw, "state", "active_serial"),
		activeRecord: v.field(bindingType, raw, "state", "active_record"),
	}
	// state.records is se_snapshot[2].
	recordsOffset, recordsSize := opaqueSourceField(v.t, bindingType, []string{"state", "records"})
	var snapshotType *btf.Struct
	if err := v.spec.Types.TypeByName("se_snapshot", &snapshotType); err != nil {
		v.t.Fatal(err)
	}
	if recordsSize != 2*int(snapshotType.Size) {
		v.t.Fatalf("binding records size %d, want two se_snapshot of %d", recordsSize, snapshotType.Size)
	}
	inRecord, _ := opaqueSourceField(v.t, snapshotType, []string{"phase"})
	for r := 0; r < 2; r++ {
		at := recordsOffset + r*int(snapshotType.Size) + inRecord
		b.phases[r] = uint64(binary.LittleEndian.Uint32(raw[at : at+4]))
		object, err := v.c.Maps["se_objects"].LookupBytes(uint32(r))
		if err != nil {
			v.t.Fatal(err)
		}
		b.pins[r] = v.field(objectType, object, "state", "pins")
	}
	return b
}

// Snapshot record phases (full/shared_snapshot.h).
const (
	opaqueSnapshotFree     = 0
	opaqueSnapshotActive   = 3
	opaqueSnapshotRetiring = 4
)

// pinsBalanced checks record r <-> object r: the ACTIVE record and a
// RETIRING record each hold exactly their object's one pin; a FREE record
// (reclaimed or rolled back) holds none. No candidate may survive.
func (b opaqueBinding) pinsBalanced() bool {
	if b.phases[b.activeRecord&1] != opaqueSnapshotActive {
		return false
	}
	for r := range b.phases {
		switch b.phases[r] {
		case opaqueSnapshotActive, opaqueSnapshotRetiring:
			if b.pins[r] != 1 {
				return false
			}
		case opaqueSnapshotFree:
			if b.pins[r] != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// reloadDump logs the account, birth witness, binding and route state of a
// failing reload round (never fails by itself, except on unreadable maps).
func (v *opaqueVerdictRun) reloadDump(label string, beforeBirths [8]uint64, before opaqueBinding, published, busy int) {
	v.t.Helper()
	tasks, works := v.accounts(label)
	births := v.birthOutcomes(label)
	v.t.Logf("%s: dump: account TASK %d WORK %d (quotas %d/%d); birth outcomes %v -> %v; binding %+v -> %+v; advance published %d busy %d",
		label, tasks, works, v.taskQuota, v.workQuota, beforeBirths, births, before, v.binding(), published, busy)
	if route, err := v.c.Maps["se_routes"].LookupBytes(uint32(0)); err == nil && len(route) == opaqueRouteAnchorLength {
		v.t.Logf("%s: dump: route 0 payload_generation=%d active_serial=%d admission_serial=%d class=%d phase=%d early=%d tasks_used=%d pins=%d unresolved=%d",
			label, binary.LittleEndian.Uint64(route[24:]), binary.LittleEndian.Uint64(route[32:]),
			binary.LittleEndian.Uint64(route[40:]), binary.LittleEndian.Uint32(route[opaqueRouteClassOffset:]),
			binary.LittleEndian.Uint32(route[opaqueRoutePhaseOffset:]), binary.LittleEndian.Uint32(route[opaqueRouteEarlyOffset:]),
			binary.LittleEndian.Uint32(route[72:]), binary.LittleEndian.Uint32(route[opaqueRoutePinsOffset:]),
			binary.LittleEndian.Uint32(route[opaqueRouteLatchOffset:]))
	}
	v.dump(label)
}

// advanceStep runs the test-only generation advance once (see
// opaque_real_live_bootstrap_advance). It never fails the test itself.
func (v *opaqueVerdictRun) advanceStep(fault uint32) (int32, error) {
	request := struct{ Fault, Enabled uint32 }{fault, 1}
	if err := v.c.Maps["opaque_real_live_advance_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		return 0, err
	}
	code, _, err := v.c.Programs["opaque_real_live_bootstrap_advance"].Test(make([]byte, 64))
	return int32(code), err
}

// reload advances the first route's generation during child churn (G025
// step 8). Generation g tickets object (g-1)%2, whose only difference is the
// policy fallback fallbacks[(g-1)%2]. The advance uses the product commit
// preflight, which refuses while any exec of the route is in flight (early
// claim, source pin, reader), so every exec is admitted, evaluated and
// terminated under one generation. Each round: two racing children (euid 0
// matches the rule; uid 1000 takes the fallback) while a goroutine retries
// the advance until it publishes once. With fault, each round first injects
// a mid-publication failure after the candidate was PREPARED and pinned,
// which must leave the last-good generation enforced (checked by a serial
// fallback child).
func (v *opaqueVerdictRun) reload(rounds int, fault bool, fallbacks [2]int) {
	v.t.Helper()
	strict := v.class == 2
	start := v.binding()
	if start.generation != 1 || start.activeRecord != 0 || start.pins != [2]uint64{1, 0} || !start.pinsBalanced() {
		v.t.Fatalf("reload: unexpected seeded binding %+v", start)
	}
	fallbackOf := func(generation uint64) int { return fallbacks[(generation-1)%2] }
	var published, busy, faults, unqualified, crossBirths int
	// park: the object carries the birth park and the cross-generation
	// qualification (G019 gaps 1 and 2; product-publisher objects).
	park := v.c.Maps[BirthParkStatsMap] != nil
	generations := map[uint64]int{}
	savedFallback := v.fallback
	defer func() { v.fallback = savedFallback }()
	for round := 0; round < rounds; round++ {
		label := fmt.Sprintf("reload round %d", round)
		before := v.binding()
		if fault {
			code, err := v.advanceStep(1)
			after := v.binding()
			// The candidate was staged in the inactive record (after
			// reclaiming a retiring one), PREPARED and pinned, then
			// failed before commit: the active tuple is unchanged and
			// the inactive record is FREE with its object unpinned.
			inactive := (before.activeRecord ^ 1) & 1
			if err != nil || code != 2 || after.generation != before.generation ||
				after.activeSerial != before.activeSerial || after.activeRecord != before.activeRecord ||
				after.phases[inactive] != opaqueSnapshotFree || !after.pinsBalanced() {
				v.t.Fatalf("%s: injected publication fault code=%d err=%v: binding %+v -> %+v, want rollback to last-good",
					label, code, err, before, after)
			}
			before = after
			faults++
			// Last-good stays enforced: a uid-1000 child takes the
			// fallback of the unchanged generation.
			v.fallback = fallbackOf(before.generation)
			wantU := 0
			if strict && v.fallback == 2 {
				wantU = 77
			}
			v.child(label+": fallback after injected fault", "FORKU\n", wantU, false)
		}
		beforeEvals, _ := v.progress()
		beforeOutcomes := v.terminalOutcomes()
		beforeBirths := v.birthOutcomes(label)
		baseTasks, baseWorks := v.accounts(label)
		stop := make(chan struct{})
		type advanceResult struct {
			published, busy int
			err             error
		}
		done := make(chan advanceResult, 1)
		if _, err := v.stdin.Write([]byte("FORKMIX:2\n")); err != nil {
			v.t.Fatal(err)
		}
		go func(delay time.Duration) {
			var r advanceResult
			time.Sleep(delay)
			for r.published == 0 {
				select {
				case <-stop:
					done <- r
					return
				default:
				}
				code, err := v.advanceStep(0)
				switch {
				case err != nil:
					r.err = err
				case code == 0:
					r.published++
				case code == 1:
					r.busy++
				default:
					r.err = fmt.Errorf("advance invariant code %d", code)
				}
				if r.err != nil {
					break
				}
			}
			<-stop
			done <- r
		}(time.Duration(round%8) * 250 * time.Microsecond)
		exits := [2]int{}
		var forkRefused [2]bool
		lines := [2]string{}
		for k := 0; k < 2; k++ {
			line, err := v.stdout.ReadString('\n')
			lines[k] = line
			var pid int
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &exits[k]); err != nil || n != 2 || pid == 0 || pid < -1 {
				close(stop)
				r := <-done
				v.reloadDump(label, beforeBirths, before, r.published, r.busy)
				v.t.Fatalf("%s: child %d line=%q err=%v stderr=%q", label, k, line, err, v.stderr.String())
			}
			forkRefused[k] = pid == -1
		}
		close(stop)
		r := <-done
		if r.err != nil {
			v.t.Fatalf("%s: %v", label, r.err)
		}
		published += r.published
		busy += r.busy
		// A birth spans two route claims: the source claim (generation g)
		// is released before the target tail call, which re-admits and
		// requires the parent WORK projection, catalogue and snapshot to
		// carry its own claim's generation. A publication that lands in
		// that gap (the preflight sees no early claim) makes the target
		// constructor fail CORRUPT (birth witness [5]): Strict refuses the
		// fork with EPERM, Audit runs the child unconstructed. Fail-closed,
		// counted exactly, and only possible in a round that published.
		births := v.birthOutcomes(label)
		for i := range births {
			births[i] -= beforeBirths[i]
		}
		refusedForks := 0
		for k := range forkRefused {
			if forkRefused[k] {
				refusedForks++
				if !strict || exits[k] != int(unix.EPERM) {
					v.reloadDump(label, beforeBirths, before, r.published, r.busy)
					v.t.Fatalf("%s: child %d fork refused (%q) under class %d", label, k, lines[k], v.class)
				}
			}
		}
		crossGeneration := int(births[5])
		// G019 gap 1: with the birth park (product-publisher objects) the
		// target constructs under the source's own claim, whose early
		// claim blocks the commit: no birth straddles a publication.
		if park && crossGeneration != 0 {
			v.reloadDump(label, beforeBirths, before, r.published, r.busy)
			v.t.Fatalf("%s: %d births straddled a publication with the birth park", label, crossGeneration)
		}
		if births[1]+births[5] != 2 || births[0]|births[2]|births[3]|births[4]|births[6]|births[7] != 0 ||
			(crossGeneration > 0 && r.published == 0) ||
			(strict && refusedForks != crossGeneration) || (!strict && refusedForks != 0) {
			v.reloadDump(label, beforeBirths, before, r.published, r.busy)
			v.t.Fatalf("%s: birth outcome deltas %v, %d refused forks, %d publications: want 2 births, constructor CORRUPT only across a publication, Strict refusals == CORRUPT constructors",
				label, births, refusedForks, r.published)
		}
		crossBirths += crossGeneration
		refunds := v.settleTasks(label, int(births[1])) // unquarantined, known role: no uncertain grant
		works, evals := v.reapRecorded()
		after := v.binding()
		if after.generation != before.generation+uint64(r.published) || !after.pinsBalanced() {
			v.t.Fatalf("%s: binding %+v -> %+v with %d publications (refusals must roll back exactly)",
				label, before, after, r.published)
		}
		// Each evaluated child has birth + evaluation WORK, and every
		// terminal completed its evaluation WORK under the generation
		// frozen at admission (completion requires the receipt generation
		// to equal the WORK view generation).
		evaluated, _ := v.progress()
		outcomes := v.terminalOutcomes()
		for i := range outcomes {
			outcomes[i] -= beforeOutcomes[i]
			v.outcomes[i] += outcomes[i]
		}
		n := len(evals)
		if evaluated-beforeEvals != uint64(n) || n > 2 || works != 2*n+(2-n) || outcomes != [4]uint64{uint64(n), 0, 0, 0} {
			v.t.Fatalf("%s: %d evaluations (%d WORK decisions), %d WORKs, outcomes %v; want one evaluation WORK per evaluated child and one birth WORK per child",
				label, evaluated-beforeEvals, n, works, outcomes)
		}
		var matched, unmatched *opaqueEvaluation
		for i := range evals {
			e := &evals[i]
			if e.generation < before.generation || e.generation > after.generation || e.mode != uint64(v.class) {
				v.t.Fatalf("%s: evaluation %+v outside generations %d..%d or class %d", label, *e, before.generation, after.generation, v.class)
			}
			generations[e.generation]++
			if e.matched != 0 {
				if matched != nil || e.deny != 0 {
					v.t.Fatalf("%s: matching evaluations %+v", label, evals)
				}
				matched = e
				continue
			}
			// Last-good: the fallback decision is exactly the policy of
			// the generation frozen at this exec's admission.
			if want := uint64(map[bool]int{true: 1}[fallbackOf(e.generation) == 2]); unmatched != nil || e.deny != want {
				v.t.Fatalf("%s: fallback evaluations %+v, want deny=%d under generation %d", label, evals, want, e.generation)
			}
			unmatched = e
		}
		// A child born under generation g whose first exec is admitted
		// under g+1: on an object without the birth park (no gap 2) it is
		// not qualified (real_owner_birth_qualify required the birth
		// receipt's generation/serial/record to equal the exec claim): it
		// is never evaluated, Strict denies it and Audit runs it
		// (fail-closed; only in a round that published). With the birth
		// park (product-publisher objects, G019 gap 2) the same route's
		// later generation admits it (se_birth_receipt_admits, counted in
		// opaque_real_birth_park[7]): it is evaluated under g+1 like any
		// other exec, so no child is left unevaluated.
		// An Audit unconstructed (cross-generation) child also runs
		// unevaluated; it is counted above, not as unqualified.
		unconstructedAudit := 0
		if !strict {
			unconstructedAudit = crossGeneration
		}
		unevaluatedN := 0
		unevaluated := func(exit int) {
			if r.published == 0 || (strict && exit != 77) || (!strict && exit != 0) {
				v.t.Fatalf("%s: unevaluated child exit %d under class %d with %d publications", label, exit, v.class, r.published)
			}
			unevaluatedN++
		}
		if matched != nil {
			if exits[0] != 0 {
				v.t.Fatalf("%s: euid-0 child allowed by its rule but exited %d", label, exits[0])
			}
		} else if !forkRefused[0] {
			unevaluated(exits[0])
		}
		// Audit never blocks; Strict allows the uid-1000 child only if
		// its frozen policy allowed it.
		if unmatched != nil {
			if want := map[bool]int{true: 77}[strict && unmatched.deny == 1]; exits[1] != want {
				v.t.Fatalf("%s: uid-1000 exit %d, want %d (class %d, frozen deny=%d)", label, exits[1], want, v.class, unmatched.deny)
			}
		} else if !forkRefused[1] {
			unevaluated(exits[1])
		}
		if park && unevaluatedN != 0 {
			v.t.Fatalf("%s: %d unevaluated children with cross-generation qualification", label, unevaluatedN)
		}
		if unevaluatedN < unconstructedAudit {
			v.t.Fatalf("%s: %d unevaluated children but %d unconstructed Audit births", label, unevaluatedN, unconstructedAudit)
		}
		unqualified += unevaluatedN - unconstructedAudit
		for _, refund := range refunds {
			v.reap("task", refund.slot, refund.cookie)
		}
		v.routeBalanced(label)
		v.parentQualified(label)
		if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
			v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
		}
		v.worksPerKind["reload"] += works
	}
	final := v.binding()
	if published < 1 || len(generations) < 2 || final.generation != 1+uint64(published) {
		v.t.Fatalf("reload: %d publications, evaluations per generation %v, final generation %d: the transition was not exercised",
			published, generations, final.generation)
	}
	if !final.pinsBalanced() {
		v.t.Fatalf("reload: final binding %+v: record/object pins unbalanced", final)
	}
	v.t.Logf("reload: %d rounds, %d publications, %d preflight refusals while in flight, %d injected faults rolled back, %d children born before and exec'd after a publication (unqualified, never evaluated, fail-closed), %d births whose source and target straddled a publication (constructor CORRUPT, fail-closed); evaluations per generation %v; final generation %d",
		rounds, published, busy, faults, unqualified, crossBirths, generations, final.generation)
}
