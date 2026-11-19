// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This opt-in test bypasses native publication only to create one synthetic
// Audit parent in the actual opaque maps. The exec reader, physical terminal
// and charged WORK consumer under test are the real default-inert candidate.
// No strict verdict, selected image or complete exec-fact set is proved.
func TestOpaqueRealOwnerLiveExecAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_CGROUP")
	helper := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_HELPER")
	sourceCompletion := os.Getenv("IG_OPAQUE_REAL_SUCCESS_SOURCE_COMPLETION") == "1"
	failureDrain := os.Getenv("IG_OPAQUE_REAL_FAILURE_SOURCE_DRAIN") == "1"
	promptFailure := os.Getenv("IG_OPAQUE_REAL_PROMPT_FAILURE") == "1"
	sameBprm := os.Getenv("IG_OPAQUE_REAL_SAME_BPRM") == "1"
	normalChurn := os.Getenv("IG_OPAQUE_REAL_NORMAL_CHURN") == "1"
	birthNegative := os.Getenv("IG_OPAQUE_REAL_BIRTH_NEGATIVE")
	effectiveUIDDivergence := os.Getenv("IG_OPAQUE_REAL_EFFECTIVE_UID_DIVERGENCE") == "1"
	sourceOwned := sourceCompletion || failureDrain || promptFailure || sameBprm || normalChurn || birthNegative != ""
	if object == "" || cgroup == "" || helper == "" {
		if sourceOwned || effectiveUIDDivergence {
			t.Fatal("source completion requires an explicit diagnostic object, isolated cgroup and helper")
		}
		t.Skip("set diagnostic object, isolated cgroup and static parent helper")
	}
	exhaust := os.Getenv("IG_OPAQUE_REAL_LIVE_EXHAUST") == "1"
	workExhaust := os.Getenv("IG_OPAQUE_REAL_LIVE_WORK_EXHAUST") == "1"
	concurrent := os.Getenv("IG_OPAQUE_REAL_LIVE_CONCURRENT") == "1"
	postPublishFault := os.Getenv("IG_OPAQUE_REAL_POST_PUBLISH_CLOSE_FAULT") == "1"
	postPublishTaskCloseFault := os.Getenv("IG_OPAQUE_REAL_POST_PUBLISH_TASK_CLOSE_FAULT") == "1"
	untrackedStrict := os.Getenv("IG_OPAQUE_REAL_UNTRACKED_STRICT") == "1"
	untrackedHelper := os.Getenv("IG_OPAQUE_REAL_UNTRACKED_HELPER")
	initialTask := os.Getenv("IG_OPAQUE_REAL_INITIAL_TASK") == "1"
	initialHelper := os.Getenv("IG_OPAQUE_REAL_INITIAL_HELPER")
	bridge := os.Getenv("IG_OPAQUE_REAL_POLICY_BRIDGE_ATTACHED") == "1"
	missingBridgeTarget := os.Getenv("IG_OPAQUE_REAL_POLICY_BRIDGE_MISSING_TARGET") == "1"
	missingStageTarget := os.Getenv("IG_OPAQUE_REAL_POLICY_STAGE_MISSING_TARGET") == "1"
	missingRuleTarget := os.Getenv("IG_OPAQUE_REAL_POLICY_RULE_MISSING_TARGET") == "1"
	uidNegative := os.Getenv("IG_OPAQUE_REAL_RULE_UID_NEGATIVE") == "1"
	bridgeChildChurn := os.Getenv("IG_OPAQUE_REAL_POLICY_BRIDGE_CHILD_CHURN") == "1"
	pendingReceipt := os.Getenv("IG_OPAQUE_REAL_LIVE_PENDING_RECEIPT") == "1"
	pendingABA := os.Getenv("IG_OPAQUE_REAL_LIVE_PENDING_ABA") == "1"
	racingTerminal := os.Getenv("IG_OPAQUE_REAL_LIVE_TERMINAL_RACE") == "1"
	producerFailure := os.Getenv("IG_OPAQUE_REAL_LIVE_TERMINAL_FAILURE") == "1"
	if effectiveUIDDivergence && (!bridge || sourceOwned || uidNegative || missingBridgeTarget || missingStageTarget || missingRuleTarget || bridgeChildChurn || racingTerminal || producerFailure || pendingReceipt || pendingABA || exhaust || workExhaust || concurrent) {
		t.Fatal("effective UID divergence requires the complete staged UID rule diagnostic alone")
	}
	if birthNegative != "" && (sourceCompletion || failureDrain || promptFailure || sameBprm || normalChurn) {
		t.Fatal("birth negative diagnostic must run alone")
	}
	if birthNegative != "" {
		validateOpaqueBirthNegativeObject(t, object, birthNegative)
	}
	if sourceOwned && (!bridge || racingTerminal || producerFailure || missingBridgeTarget || missingStageTarget || missingRuleTarget || uidNegative || bridgeChildChurn || pendingReceipt || pendingABA || exhaust || workExhaust || concurrent) {
		t.Fatal("source completion requires synthetic Audit bridge with retained target alone")
	}
	if failureDrain && sourceCompletion || promptFailure && (failureDrain || sourceCompletion) || sameBprm && (failureDrain || sourceCompletion || promptFailure) || normalChurn && (failureDrain || sourceCompletion || promptFailure || sameBprm) {
		t.Fatal("select only one source-owned completion diagnostic")
	}
	if postPublishFault && postPublishTaskCloseFault {
		t.Fatal("select only one post-publication close fault")
	}
	if (postPublishFault || postPublishTaskCloseFault) && !concurrent {
		t.Fatal("post-publication close fault requires strict concurrent-parent setup")
	}
	if untrackedStrict && (!concurrent || untrackedHelper == "" ||
		postPublishFault || postPublishTaskCloseFault) {
		t.Fatal("untracked strict-parent proof requires only the strict parent setup and helper")
	}
	if initialTask && (!concurrent || initialHelper == "" ||
		untrackedStrict || postPublishFault || postPublishTaskCloseFault) {
		t.Fatal("initial TASK diagnostic requires only strict concurrent setup and helper")
	}
	if producerFailure && !racingTerminal {
		t.Fatal("failure terminal requires the retained reader race diagnostic")
	}
	if racingTerminal && (!bridge || missingBridgeTarget || bridgeChildChurn || pendingReceipt || pendingABA || exhaust || workExhaust || concurrent) {
		t.Fatal("terminal race requires the staged bridge alone")
	}
	if missingStageTarget && (!bridge || missingBridgeTarget) {
		t.Fatal("missing evaluator stage requires the source policy target")
	}
	if missingRuleTarget && (!bridge || missingBridgeTarget || missingStageTarget) {
		t.Fatal("missing rule target requires the installed source and stage targets")
	}
	if uidNegative && (!bridge || missingBridgeTarget || missingStageTarget || missingRuleTarget) {
		t.Fatal("negative UID rule requires all policy targets installed")
	}
	if pendingABA && (!bridgeChildChurn || pendingReceipt) {
		t.Fatal("pending ABA requires staged child churn alone")
	}
	if pendingReceipt && (!bridge || !missingBridgeTarget || bridgeChildChurn || exhaust || workExhaust || concurrent) {
		t.Fatal("pending receipt diagnostic requires the staged bridge with no target")
	}
	if missingBridgeTarget && !bridge {
		t.Fatal("missing-target diagnostic requires staged bridge mode")
	}
	if bridgeChildChurn && (!bridge || missingBridgeTarget) {
		t.Fatal("staged child churn requires an installed bridge target")
	}
	churn := 1
	if normalChurn {
		churn = 4097
	}
	if raw := os.Getenv("IG_OPAQUE_REAL_LIVE_CHURN"); raw != "" {
		var err error
		churn, err = strconv.Atoi(raw)
		if err != nil || churn < 1 || churn > 4097 {
			t.Fatalf("invalid real-map churn count %q", raw)
		}
	}
	if (exhaust || workExhaust || concurrent || bridge && !bridgeChildChurn && !normalChurn) && churn != 1 ||
		(exhaust && workExhaust) || (concurrent && (exhaust || workExhaust)) {
		t.Fatal("strict quota diagnostics must run separately from churn and each other")
	}
	if bridge && (exhaust || workExhaust || concurrent) {
		t.Fatal("policy bridge attached diagnostic must run alone")
	}
	if os.Geteuid() != 0 ||
		!strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-reallive-") ||
		!filepath.IsAbs(helper) {
		t.Fatal("root, dedicated ig15-g005-reallive-* cgroup and absolute helper required")
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil || st.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(os.Getpid())+"\n")) {
		t.Fatalf("controller must remain outside isolated cgroup: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if effectiveUIDDivergence && spec.Maps["opaque_real_owner_rule_progress"] == nil {
		t.Fatal("effective UID divergence requires the real rule-window object")
	}
	selected := map[string]*ebpf.ProgramSpec{}
	var kernelTypes *btf.Spec
	for _, name := range []string{
		"opaque_real_live_bootstrap_control",
		"opaque_real_live_bootstrap_birth",
		"opaque_real_live_bootstrap_qualify",
		"opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_target_candidate",
		"opaque_real_owner_child_final_free_candidate",
		"opaque_real_owner_reader_begin_probe",
		"opaque_real_owner_reader_success_probe",
		"opaque_real_owner_failure_outer_enter",
		"opaque_real_owner_failure_handler_enter",
		"opaque_real_owner_failure_handler_exit",
		"opaque_real_owner_failure_outer_exit",
		"opaque_real_owner_work_completion_probe",
		"opaque_real_owner_work_retry_probe",
		"opaque_real_live_reap_work",
		"opaque_real_live_reap_task",
	} {
		if sourceOwned && (name == "opaque_real_owner_work_completion_probe" || name == "opaque_real_owner_work_retry_probe") {
			continue // No controller completion program exists in this collection.
		}
		if spec.Programs[name] == nil {
			t.Fatalf("missing real-map diagnostic %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	if promptFailure {
		const name = "opaque_real_owner_failure_fexit_probe"
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.Tracing || program.AttachType != ebpf.AttachTraceFExit || program.AttachTo != "bprm_execve" || program.Flags != 0 {
			t.Fatal("prompt failure requires exact non-sleepable bprm_execve fexit program")
		}
		kernelTypes, err = btf.LoadKernelSpec()
		if err != nil {
			t.Fatal(err)
		}
		var target *btf.Func
		if err := kernelTypes.TypeByName(program.AttachTo, &target); err != nil {
			t.Fatalf("prompt failure target lacks unique kernel BTF FUNC: %v", err)
		}
		if err := opaquePromptFailurePrototype(target); err != nil {
			t.Fatalf("prompt failure target ABI: %v", err)
		}
		selected[name] = program
	}
	if bridge {
		if missingStageTarget && spec.Maps["opaque_real_owner_policy_stage_targets"] == nil {
			t.Fatal("missing evaluator stage requires the diagnostic stage map")
		}
		for _, name := range []string{
			"opaque_real_owner_policy_target_candidate",
			"opaque_real_owner_policy_seed_diagnostic",
		} {
			if spec.Programs[name] == nil {
				t.Fatalf("missing staged policy diagnostic %s", name)
			}
			selected[name] = spec.Programs[name]
		}
		if spec.Maps["opaque_real_owner_policy_stage_targets"] != nil {
			const stage = "opaque_real_owner_policy_stage_target_candidate"
			if spec.Programs[stage] == nil {
				t.Fatalf("missing staged evaluator target %s", stage)
			}
			selected[stage] = spec.Programs[stage]
		}
		if spec.Maps["opaque_real_owner_rule_targets"] != nil && !missingRuleTarget {
			const rule = "opaque_real_owner_rule_target_candidate"
			if spec.Programs[rule] == nil {
				t.Fatalf("missing staged rule target %s", rule)
			}
			selected[rule] = spec.Programs[rule]
		}
	}
	if pendingReceipt || pendingABA {
		for _, name := range []string{"opaque_real_pending_receipt_cleanup"} {
			if spec.Programs[name] == nil {
				t.Fatalf("missing pending receipt diagnostic %s", name)
			}
			selected[name] = spec.Programs[name]
		}
	}
	if racingTerminal || sourceOwned {
		for _, name := range []string{
			"opaque_real_owner_terminal_retain_target",
			"opaque_real_owner_terminal_race_complete",
		} {
			if sourceOwned && name == "opaque_real_owner_terminal_race_complete" {
				continue
			}
			if spec.Programs[name] == nil {
				t.Fatalf("missing terminal race diagnostic %s", name)
			}
			selected[name] = spec.Programs[name]
		}
	}
	if initialTask {
		name := "opaque_real_owner_initial_task_diagnostic"
		if spec.Programs[name] == nil {
			t.Fatalf("missing %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	if normalChurn || birthNegative != "" {
		if err := selectOpaqueNormalChurnBirthPrograms(spec, selected); err != nil {
			t.Fatal(err)
		}
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20, KernelTypes: kernelTypes},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("attached real-map candidate verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
	}()
	bootstrapGate := struct {
		Cgroup, Scope           uint64
		Enabled, ExecutionClass uint32
	}{st.Ino, 10, 1, 0}
	if exhaust || workExhaust || concurrent {
		bootstrapGate.ExecutionClass = 2
	}
	if err := collection.Maps["opaque_real_live_bootstrap_gate"].Update(
		uint32(0), bootstrapGate, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_child_gate"].Update(
		uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if bridge {
		config := sharedNodeWire{
			NodeCookie: 11, Nonce: 22, ABI: 3,
			ProfileVersion: 1, Bindings: 2, Objects: 2, Cells: 512,
			Slots: [4]uint32{2},
		}
		if err := collection.Maps["se_configuration"].Update(uint32(0), config,
			ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := collection.Maps["se_configuration"].Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"opaque_real_live_bootstrap_gate",
		"opaque_real_owner_child_gate", "se_opaque_payload_zero",
		"se_opaque_work_zero",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	code, _, err := collection.Programs["opaque_real_live_bootstrap_control"].Test(make([]byte, 64))
	if err != nil || code != 0 {
		t.Fatalf("test-only control seed: code=%d err=%v", code, err)
	}
	if bridge {
		if uidNegative {
			uidMap := collection.Maps["opaque_real_owner_rule_uid_expect"]
			if uidMap == nil {
				t.Fatal("negative UID diagnostic requires the rule UID map")
			}
			if err := uidMap.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		code, _, err := collection.Programs["opaque_real_owner_policy_seed_diagnostic"].Test(
			make([]byte, 64))
		if err != nil || code != 0 {
			t.Fatalf("test-only real policy seed: code=%d err=%v", code, err)
		}
		if collection.Maps["opaque_real_owner_rule_uid_expect"] != nil {
			uidBlob, err := collection.Maps["se_arena"].LookupBytes(uint32(10))
			wantUID := uint64(0)
			if uidNegative {
				wantUID = 1
			}
			if err != nil || len(uidBlob) < 8 ||
				binary.LittleEndian.Uint64(uidBlob[:8]) != wantUID {
				t.Fatalf("test-only UID rule cell: got=%x want=%d err=%v",
					uidBlob[:min(len(uidBlob), 8)], wantUID, err)
			}
		}
		if !missingBridgeTarget {
			target := "opaque_real_owner_policy_target_candidate"
			if racingTerminal || sourceOwned {
				target = "opaque_real_owner_terminal_retain_target"
			}
			if err := collection.Maps["opaque_real_owner_policy_targets"].Update(uint32(0),
				collection.Programs[target],
				ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		if err := collection.Maps["opaque_real_owner_policy_targets"].Freeze(); err != nil {
			t.Fatal(err)
		}
		if stageMap := collection.Maps["opaque_real_owner_policy_stage_targets"]; stageMap != nil {
			if !missingStageTarget {
				if err := stageMap.Update(uint32(0),
					collection.Programs["opaque_real_owner_policy_stage_target_candidate"],
					ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := stageMap.Freeze(); err != nil {
				t.Fatal(err)
			}
		}
		if ruleMap := collection.Maps["opaque_real_owner_rule_targets"]; ruleMap != nil {
			if !missingRuleTarget {
				if err := ruleMap.Update(uint32(0),
					collection.Programs["opaque_real_owner_rule_target_candidate"],
					ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := ruleMap.Freeze(); err != nil {
				t.Fatal(err)
			}
		}
	}
	var locator uint64
	if err := collection.Maps["se_route_index"].Lookup(st.Ino, &locator); err != nil ||
		locator != uint64(1)<<32 {
		t.Fatalf("test-only route index: locator=%#x err=%v", locator, err)
	}
	attachLSM := func(name string) link.Link {
		t.Helper()
		l, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
		return l
	}
	attachLSM("opaque_real_owner_child_final_free_candidate")
	qualifyLink := attachLSM("opaque_real_live_bootstrap_qualify")
	birthLink := attachLSM("opaque_real_live_bootstrap_birth")
	timeout := 45 * time.Second
	if churn > 1 || exhaust || workExhaust || concurrent {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if concurrent {
		runOpaqueRealConcurrentBoundary(t, collection, attachLSM,
			birthLink, qualifyLink, ctx, cgroup, helper,
			postPublishFault, postPublishTaskCloseFault,
			untrackedStrict, untrackedHelper, initialTask, initialHelper)
		return
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
		"echo $$ > \"$1/cgroup.procs\" || exit 97; \"$2\" <&0 & child=$!; wait \"$child\"",
		"ig15-real-live-launcher", cgroup, helper)
	if effectiveUIDDivergence {
		cmd.Env = append(os.Environ(), "IG_OPAQUE_EFFECTIVE_UID_DIVERGENCE=1")
	}
	if producerFailure || failureDrain || promptFailure {
		path := filepath.Join(t.TempDir(), "invalid-executable")
		if err := os.WriteFile(path, []byte("invalid executable image\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(os.Environ(), "IG_OPAQUE_FAIL_EXEC_PATH="+path)
	}
	var scriptPath string
	if sameBprm {
		if strings.ContainsAny(helper, " \t\r\n") || len(helper) > 120 {
			t.Fatal("same-bprm shebang requires a short helper path without whitespace")
		}
		scriptPath = filepath.Join(t.TempDir(), "direct-script")
		if err := os.WriteFile(scriptPath, []byte("#!"+helper+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(os.Environ(), "IG_OPAQUE_SCRIPT_PATH="+scriptPath)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil || ready != "READY\n" {
		t.Fatalf("seeded parent: line=%q err=%v stderr=%q", ready, err, stderr.String())
	}
	var divergentPID int
	if effectiveUIDDivergence {
		divergentPID = opaqueSetDivergentUIDs(t, stdin, reader)
	}
	if !bridgeChildChurn {
		if err := birthLink.Close(); err != nil {
			t.Fatal(err)
		}
		if err := qualifyLink.Close(); err != nil {
			t.Fatal(err)
		}
	}
	keys := collection.Maps["se_opaque_keys"].Iterate()
	var physical, taskLocator uint64
	if !keys.Next(&physical, &taskLocator) || keys.Err() != nil ||
		physical == 0 || taskLocator == 0 || keys.Next(&physical, &taskLocator) {
		t.Fatalf("expected one real opaque TASK: key=%#x locator=%#x err=%v", physical, taskLocator, keys.Err())
	}
	var payload [1280]byte
	if err := collection.Maps["se_opaque_payload"].Lookup(uint32(0), &payload); err != nil ||
		binary.LittleEndian.Uint32(payload[4:8]) != 5 ||
		binary.LittleEndian.Uint64(payload[16:24]) != 10 {
		t.Fatalf("synthetic parent not qualified in real TASK: flags=%d scope=%d err=%v",
			binary.LittleEndian.Uint32(payload[4:8]),
			binary.LittleEndian.Uint64(payload[16:24]), err)
	}
	if exhaust || workExhaust {
		runOpaqueRealCreditExhaustion(t, collection, attachLSM, stdin,
			reader, cmd, physical, workExhaust)
		return
	}
	if pendingReceipt {
		charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
		if err != nil || len(charge) < 8 {
			t.Fatalf("qualified parent TASK charge: raw=%x err=%v", charge, err)
		}
		cookie := binary.LittleEndian.Uint64(charge[:8])
		if cookie == 0 || cookie == ^uint64(0) || taskLocator == ^uint64(0) {
			t.Fatal("cannot construct distinct stale receipt identity")
		}
		selector := struct{ Physical, StaleCookie, StaleLocator, Cgroup uint64 }{
			physical, cookie + 1, taskLocator + 1, st.Ino,
		}
		if err := collection.Maps["opaque_real_pending_selector"].Update(
			uint32(0), selector, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := collection.Maps["opaque_real_pending_selector"].Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	kallsyms, err := os.Open("/proc/kallsyms")
	if err != nil {
		t.Fatal(err)
	}
	outerExecSymbol, symbolErr := opaqueDiagnosticExecOuterSymbol(kallsyms)
	if symbolErr != nil {
		kallsyms.Close()
		t.Fatalf("resolve diagnostic outer exec source: %v", symbolErr)
	}
	if _, err := kallsyms.Seek(0, io.SeekStart); err != nil {
		kallsyms.Close()
		t.Fatal(err)
	}
	handlerSymbol, symbolErr := opaqueDiagnosticExecHandlerSymbol(kallsyms,
		os.Getenv("IG_OPAQUE_REAL_LIVE_HANDLER_SYMBOL"))
	kallsyms.Close()
	if symbolErr != nil {
		t.Fatalf("resolve diagnostic handler source: %v", symbolErr)
	}
	t.Logf("diagnostic outer exec source: %s", outerExecSymbol)
	t.Logf("diagnostic handler source: %s (not product qualification)", handlerSymbol)
	attachKprobe := func(symbol, name string, ret bool) {
		t.Helper()
		var l link.Link
		var err error
		if ret {
			l, err = link.Kretprobe(symbol, collection.Programs[name], nil)
		} else {
			l, err = link.Kprobe(symbol, collection.Programs[name], nil)
		}
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
	}
	attachKprobe(outerExecSymbol, "opaque_real_owner_failure_outer_exit", true)
	attachKprobe(handlerSymbol, "opaque_real_owner_failure_handler_exit", true)
	attachKprobe(handlerSymbol, "opaque_real_owner_failure_handler_enter", false)
	attachKprobe(outerExecSymbol, "opaque_real_owner_failure_outer_enter", false)
	successLink, err := link.AttachTracing(link.TracingOptions{
		Program: collection.Programs["opaque_real_owner_reader_success_probe"],
	})
	if err != nil {
		t.Fatalf("attach success source: %v", err)
	}
	links = append(links, successLink)
	if promptFailure {
		failureLink, err := link.AttachTracing(link.TracingOptions{Program: collection.Programs["opaque_real_owner_failure_fexit_probe"]})
		if err != nil {
			t.Fatalf("attach prompt failure source: %v", err)
		}
		links = append(links, failureLink)
	}
	attachLSM("opaque_real_owner_reader_begin_probe")
	var birthPrior link.Link
	if birthNegative == "prior-denial" {
		// Trampoline links are inserted at the head: attach last to execute
		// before the candidate. The live state assertion verifies this order.
		birthPrior = attachOpaqueBirthPriorDenial(t, st.Ino)
	}
	if bridgeChildChurn {
		runOpaqueRealPolicyBridgeChildChurn(t, collection, stdin, reader,
			cmd, physical, taskLocator, st.Ino, &stderr, churn, pendingABA)
		return
	}
	if birthNegative != "" {
		runOpaqueBirthNegativeAttached(t, collection, spec, attachLSM, stdin, reader, cmd, physical, &stderr, birthNegative, cgroup, birthPrior)
		return
	}
	var beforeInvocation uint64
	if sameBprm {
		var taskType *btf.Struct
		if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
			t.Fatal(err)
		}
		offset, size := opaqueSourceField(t, taskType, []string{"next_invocation"})
		if size != 8 || offset+size > len(payload) {
			t.Fatal("invalid invocation field")
		}
		beforeInvocation = binary.LittleEndian.Uint64(payload[offset : offset+size])
	}
	command := "EXEC\n"
	if sameBprm {
		command = "SCRIPT\n"
	}
	if producerFailure || failureDrain || promptFailure {
		command = "FAIL\n"
	}
	if _, err := stdin.Write([]byte(command)); err != nil {
		t.Fatal(err)
	}
	after, err := reader.ReadString('\n')
	expected := "AFTER\n"
	if producerFailure || failureDrain || promptFailure {
		expected = "FAILED:" + strconv.Itoa(int(syscall.ENOEXEC)) + "\n"
	}
	if err != nil || after != expected {
		t.Fatalf("live second exec: line=%q err=%v stderr=%q", after, err, stderr.String())
	}
	if effectiveUIDDivergence {
		opaqueAssertDivergentUIDs(t, divergentPID)
		t.Log("actual helper retains real UID 1000 and effective UID 0 across observed exec; staged rule must match effective UID 0")
	}
	if pendingReceipt {
		runOpaqueRealPendingReceiptAttached(t, collection, stdin,
			cmd, physical, taskLocator, &stderr)
		return
	}
	if normalChurn {
		runOpaqueRealNormalChurnAttached(t, collection, spec, attachLSM, stdin, reader, cmd, physical, taskLocator, &stderr, churn)
		return
	}
	if sameBprm {
		runOpaqueRealSameBprmAttached(t, collection, spec, stdin, cmd, physical, taskLocator, beforeInvocation, scriptPath, helper, &stderr)
		return
	}
	if promptFailure {
		runOpaqueRealPromptFailureAttached(t, collection, spec, stdin, reader, cmd, physical, taskLocator, &stderr)
		return
	}
	if failureDrain {
		runOpaqueRealFailureSourceDrainAttached(t, collection, spec, stdin, reader, cmd, physical, taskLocator, &stderr)
		return
	}
	if sourceCompletion {
		runOpaqueRealSuccessSourceCompletionAttached(t, collection, spec, stdin, cmd, physical, taskLocator, &stderr)
		return
	}
	if racingTerminal {
		runOpaqueRealTerminalRaceAttached(t, collection, stdin, cmd,
			physical, taskLocator, &stderr, producerFailure)
		return
	}
	if bridge {
		runOpaqueRealPolicyBridgeAttached(t, collection, stdin, cmd,
			physical, taskLocator, &stderr,
			!missingBridgeTarget && !missingStageTarget && !missingRuleTarget,
			!missingBridgeTarget, missingRuleTarget, !uidNegative)
		return
	}
	var receipt struct {
		Physical, Bprm, Cookie, Locator, Invocation, Scope, Generation uint64
		Phase, Reserved                                                uint32
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); err != nil ||
		receipt.Physical != physical || receipt.Bprm == 0 || receipt.Cookie == 0 ||
		receipt.Locator != taskLocator || receipt.Invocation == 0 ||
		receipt.Scope != 10 || receipt.Generation != 1 ||
		receipt.Phase != 2 || receipt.Reserved != 0 {
		t.Fatalf("live source-owned success receipt: %+v err=%v", receipt, err)
	}
	parentCookie, parentInvocation := receipt.Cookie, receipt.Invocation
	if err := collection.Maps["opaque_real_owner_work_completion_selector"].Update(
		uint32(0), physical, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_work_completion_gate"].Update(
		uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"opaque_real_owner_work_completion_selector",
		"opaque_real_owner_work_completion_gate",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, err := collection.Programs["opaque_real_owner_work_completion_probe"].Test(
		make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("live charged WORK completion: code=%d err=%v", code, err)
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("completed source receipt retained: %+v err=%v", receipt, err)
	}
	charge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
	if err != nil || len(charge) < 8 {
		t.Fatalf("charged WORK identity: raw=%x err=%v", charge, err)
	}
	workCookie := binary.LittleEndian.Uint64(charge[:8])
	if workCookie == 0 {
		t.Fatal("completed WORK lost its still-charged reaper identity")
	}
	reapRequest := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{workCookie, 0, 1}
	if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
		uint32(0), reapRequest, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	returned := false
	for i := 0; i < 10; i++ {
		code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
		if err != nil || code > 1 {
			t.Fatalf("actual WORK reap step %d: code=%d err=%v", i, code, err)
		}
		if code == 1 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("actual WORK reaper did not return its exact credit")
	}
	if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("charged WORK not refunded: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["opaque_real_owner_child_targets"].Update(uint32(0),
		collection.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	attachLSM("opaque_real_owner_child_source_candidate")
	var childPhysical, childTaskCookie, childWorkCookie uint64
	lastTaskCookie, lastWorkCookie := parentCookie, workCookie
	seenPhysical := make(map[uint64]struct{ cookie, locator uint64 })
	addressReuse := 0
	for iteration := 0; iteration < churn; iteration++ {
		if _, err := stdin.Write([]byte("FORK\n")); err != nil {
			t.Fatalf("child %d fork request: %v", iteration, err)
		}
		forked, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(forked, "FORKED:") ||
			!strings.HasSuffix(forked, ":0\n") {
			t.Fatalf("real child source/target fork: line=%q err=%v stderr=%q", forked, err, stderr.String())
		}
		childPhysical = 0
		var childLocator uint64
		keys = collection.Maps["se_opaque_keys"].Iterate()
		for keys.Next(&taskLocator, &locator) {
			if taskLocator != physical {
				if childPhysical != 0 {
					t.Fatal("more than one newly charged real child")
				}
				childPhysical, childLocator = taskLocator, locator
			}
		}
		if keys.Err() != nil || childPhysical == 0 || childLocator&((1<<14)-1) != 1 {
			t.Fatalf("real source/target did not publish a charged child: key=%#x locator=%#x err=%v", childPhysical, childLocator, keys.Err())
		}
		childWorkCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
		if err != nil || len(childWorkCharge) < 8 {
			t.Fatalf("real child WORK charge: raw=%x err=%v", childWorkCharge, err)
		}
		childWorkCookie = binary.LittleEndian.Uint64(childWorkCharge[:8])
		if childWorkCookie <= lastWorkCookie {
			t.Fatalf("real child WORK cookie did not advance: previous=%d child=%d", lastWorkCookie, childWorkCookie)
		}
		lastWorkCookie = childWorkCookie
		reapRequest.Cookie = childWorkCookie
		if err := collection.Maps["opaque_real_live_work_reap_request"].Update(uint32(0), reapRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned = false
		for i := 0; i < 10; i++ {
			code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
			if err != nil || code > 1 {
				t.Fatalf("real child WORK reap step %d: code=%d err=%v", i, code, err)
			}
			if code == 1 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatal("real child source WORK credit was not returned")
		}
		if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
			len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
			t.Fatalf("real child WORK account not empty: raw=%x err=%v", raw, err)
		}
		childTaskCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
		if err != nil || len(childTaskCharge) < 8 {
			t.Fatalf("real child TASK charge: raw=%x err=%v", childTaskCharge, err)
		}
		childTaskCookie = binary.LittleEndian.Uint64(childTaskCharge[:8])
		if childTaskCookie <= lastTaskCookie {
			t.Fatalf("real child TASK cookie did not advance: previous=%d child=%d", lastTaskCookie, childTaskCookie)
		}
		if previous, reused := seenPhysical[childPhysical]; reused {
			addressReuse++
			if childTaskCookie <= previous.cookie || childLocator == previous.locator {
				t.Fatalf("reused physical TASK %#x retained stale identity: old=%d/%#x new=%d/%#x",
					childPhysical, previous.cookie, previous.locator, childTaskCookie, childLocator)
			}
			staleRequest := struct {
				Cookie        uint64
				Slot, Enabled uint32
			}{previous.cookie, 1, 1}
			if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
				uint32(0), staleRequest, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(
				make([]byte, 64)); err != nil || code != 4 {
				t.Fatalf("stale TASK cookie on reused physical %#x: code=%d err=%v",
					childPhysical, code, err)
			}
			var currentLocator uint64
			if err := collection.Maps["se_opaque_keys"].Lookup(childPhysical, &currentLocator); err != nil ||
				currentLocator != childLocator {
				t.Fatalf("stale reaper touched new physical owner %#x: want=%#x got=%#x err=%v",
					childPhysical, childLocator, currentLocator, err)
			}
			if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil ||
				len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != 2 ||
				binary.LittleEndian.Uint32(raw[8:12]) != 0 {
				t.Fatalf("stale TASK reaper changed/faulted account: raw=%x err=%v", raw, err)
			}
		}
		seenPhysical[childPhysical] = struct{ cookie, locator uint64 }{childTaskCookie, childLocator}
		lastTaskCookie = childTaskCookie
		childDeathDeadline := time.Now().Add(10 * time.Second)
		for {
			meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(1))
			if err != nil || len(meta) != 128 {
				t.Fatalf("real child TASK metadata: len=%d err=%v", len(meta), err)
			}
			if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
				break
			}
			if time.Now().After(childDeathDeadline) {
				t.Fatalf("real child task_free did not publish DEAD: meta=%x", meta)
			}
			time.Sleep(20 * time.Millisecond)
		}
		childTaskRequest := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{childTaskCookie, 1, 1}
		if err := collection.Maps["opaque_real_live_task_reap_request"].Update(uint32(0), childTaskRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned = false
		for i := 0; i < 20; i++ {
			code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
			if err != nil || code == 4 || code > 4 {
				t.Fatalf("real child TASK reap visit %d: code=%d err=%v", i, code, err)
			}
			if code == 2 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatal("real child TASK credit was not returned")
		}
		if err := collection.Maps["se_opaque_keys"].Lookup(childPhysical, &childLocator); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("real child key retained after refund: locator=%#x err=%v", childLocator, err)
		}
		if err := collection.Maps["se_exec_terminal_receipts"].Lookup(childPhysical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("dead child terminal retained after authenticated reaper: %+v err=%v", receipt, err)
		}
		if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil ||
			len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != 1 ||
			binary.LittleEndian.Uint32(raw[8:12]) != 0 {
			t.Fatalf("child %d left charged/faulted TASK account: raw=%x err=%v", iteration, raw, err)
		}
		if raw, err := collection.Maps["se_routes"].LookupBytes(uint32(0)); err != nil ||
			len(raw) < 68 || binary.LittleEndian.Uint32(raw[64:68]) != 0 {
			t.Fatalf("child %d left original route claim: raw=%x err=%v", iteration, raw, err)
		}
		if iteration == 0 || iteration == churn-1 || (iteration+1)%512 == 0 {
			t.Logf("real child churn %d/%d: task_cookie=%d work_cookie=%d address_reuses=%d", iteration+1, churn, childTaskCookie, childWorkCookie, addressReuse)
		}
	}
	if os.Getenv("IG_OPAQUE_REAL_LIVE_REQUIRE_ABA") == "1" && addressReuse == 0 {
		t.Fatalf("no physical task address reuse observed across %d births; ABA not demonstrated", churn)
	}
	t.Logf("real physical task address reuse: %d reused births among %d; unique addresses=%d",
		addressReuse, churn, len(seenPhysical))
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("tracked parent exit: %v stderr=%q", err, stderr.String())
	}
	// task_free runs on the final task_struct release, which may trail
	// waitpid. Do not ask the reaper to invent source-owned death receipts.
	deathDeadline := time.Now().Add(10 * time.Second)
	for {
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) != 128 {
			t.Fatalf("dead TASK metadata: len=%d err=%v", len(meta), err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			t.Logf("actual task_free: cleanup=%#x reader_holds=%d work_refs=%d error=%d",
				binary.LittleEndian.Uint32(meta[80:84]),
				binary.LittleEndian.Uint32(meta[24:28]),
				binary.LittleEndian.Uint32(meta[72:76]),
				binary.LittleEndian.Uint32(meta[84:88]))
			break
		}
		if time.Now().After(deathDeadline) {
			t.Fatalf("task_free did not publish DEAD: phase=%d meta=%x",
				binary.LittleEndian.Uint32(meta[4:8]), meta)
		}
		time.Sleep(20 * time.Millisecond)
	}
	taskRequest := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{parentCookie, 0, 1}
	if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
		uint32(0), taskRequest, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	returned = false
	for i := 0; i < 20; i++ {
		code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
		t.Logf("TASK reap visit %d: code=%d err=%v", i, code, err)
		if err != nil || code == 4 || code > 4 {
			t.Fatalf("actual TASK reap visit %d: code=%d err=%v", i, code, err)
		}
		if code == 2 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("actual TASK reaper did not return its exact credit")
	}
	if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("charged TASK not refunded: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &taskLocator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("dead TASK key retained after refund: locator=%#x err=%v", taskLocator, err)
	}
	t.Logf("real-map attached Audit exec, %d real child source/target births, WORK and TASK refunds: parent=%#x/%d final_child=%#x/%d invocation=%d final_work_cookie=%d", churn, physical, parentCookie, childPhysical, childTaskCookie, parentInvocation, childWorkCookie)
}
