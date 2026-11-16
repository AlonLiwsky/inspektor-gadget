// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// sharedPredicateRule returns one allow rule using exactly the predicate kind.
func sharedPredicateRule(kind SharedPredicateKind) fullpolicy.Rule {
	yes := true
	r := fullpolicy.Rule{Name: string(kind), Action: fullpolicy.Allow}
	switch kind {
	case SharedPredicateActorRole:
		r.Actor.Role = []string{"app"}
	case SharedPredicateActorUID:
		r.Actor.UID = []int64{0}
	case SharedPredicateActorContainer:
		r.Actor.Container = []string{"app"}
	case SharedPredicateActorPath:
		r.Actor.Path = []string{"/bin/sh"}
	case SharedPredicateActorImage:
		r.Actor.FromImage = &yes
	case SharedPredicateActorAncestor:
		r.Actor.Ancestor = &fullpolicy.Ancestor{Path: []string{"/bin/sh"}, Depth: 1}
	case SharedPredicateTargetPath:
		r.Target.Path = []string{"/bin/ls"}
	case SharedPredicateTargetImage:
		r.Target.FromImage = &yes
	case SharedPredicateTargetFSType:
		r.Target.FSType = []string{"tmpfs"}
	case SharedPredicateTargetStdin:
		r.Target.Argv = &fullpolicy.Argv{StdinIsPipe: &yes}
	case SharedPredicateTargetArgv:
		r.Target.Argv = &fullpolicy.Argv{Contains: []string{"-c"}}
	default:
		panic("unknown predicate kind " + kind)
	}
	return r
}

func sharedPredicatePolicy(rules ...fullpolicy.Rule) *fullpolicy.Policy {
	return &fullpolicy.Policy{ID: "p", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Deny, Rules: rules}
}

// TestSharedProductFactTableComplete: every predicate kind the enumerator can
// report has a table entry, and the table names no other kind.
func TestSharedProductFactTableComplete(t *testing.T) {
	yes := true
	all := sharedPredicateKinds(
		fullpolicy.Actor{Path: []string{"/a"}, FromImage: &yes, Ancestor: &fullpolicy.Ancestor{}, Role: []string{"r"}, UID: []int64{0}, Container: []string{"c"}},
		fullpolicy.Target{Path: []string{"/t"}, FromImage: &yes, FSType: []string{"tmpfs"}, Argv: &fullpolicy.Argv{Contains: []string{"x"}, StdinIsPipe: &yes}, SetRole: "r"},
	)
	got := slices.Sorted(maps.Keys(SharedProductFactSupport()))
	slices.Sort(all)
	if !slices.Equal(all, got) {
		t.Fatalf("enumerated kinds %v, table %v", all, got)
	}
	if kinds := sharedPredicateKinds(fullpolicy.Actor{}, fullpolicy.Target{SetRole: "r"}); len(kinds) != 0 {
		t.Fatalf("SetRole is an effect, enumerated as %v", kinds)
	}
}

// TestSharedProductFactTableToday pins today's capabilities (G020 part 4):
// roles, euid, the container name, the per-pass path, ancestor, fs class,
// stdin and image facts are produced; argv is refused.
func TestSharedProductFactTableToday(t *testing.T) {
	want := map[SharedPredicateKind]SharedFactSupport{
		SharedPredicateActorRole:      SharedFactSupported,
		SharedPredicateActorUID:       SharedFactSupported,
		SharedPredicateActorContainer: SharedFactSupported,
		SharedPredicateActorPath:      SharedFactSupported,
		SharedPredicateActorImage:     SharedFactSupported,
		SharedPredicateActorAncestor:  SharedFactSupported,
		SharedPredicateTargetPath:     SharedFactSupported,
		SharedPredicateTargetImage:    SharedFactSupported,
		SharedPredicateTargetFSType:   SharedFactSupported,
		SharedPredicateTargetStdin:    SharedFactSupported,
		SharedPredicateTargetArgv:     SharedFactRefused,
	}
	if got := SharedProductFactSupport(); !maps.Equal(got, want) {
		t.Fatalf("fact table %v, want %v", got, want)
	}
	// The exported table is a copy.
	SharedProductFactSupport()[SharedPredicateTargetArgv] = SharedFactSupported
	if sharedProductFactSupport[SharedPredicateTargetArgv] != SharedFactRefused {
		t.Fatal("exported table aliases the admission switch")
	}
}

// TestSharedPredicateAdmissionFollowsTable: each kind is admitted exactly
// when its entry is supported, and flipping the entry flips admission (the
// table is the single switch).
func TestSharedPredicateAdmissionFollowsTable(t *testing.T) {
	saved := maps.Clone(sharedProductFactSupport)
	t.Cleanup(func() { sharedProductFactSupport = saved })
	for kind := range saved {
		for _, support := range []SharedFactSupport{SharedFactSupported, SharedFactNotYet, SharedFactRefused} {
			sharedProductFactSupport = maps.Clone(saved)
			sharedProductFactSupport[kind] = support
			err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(kind)))
			if support == SharedFactSupported {
				if err != nil {
					t.Fatalf("%s supported: %v", kind, err)
				}
				continue
			}
			var e *SharedPredicateUnsupportedError
			if !errors.Is(err, ErrSharedPredicateUnsupported) || !errors.As(err, &e) {
				t.Fatalf("%s %s: %v", kind, support, err)
			}
			if e.Kind != kind || e.Rule != 0 || e.Exception != -1 || e.Policy != "p" || e.Support != support {
				t.Fatalf("%s %s: %+v", kind, support, e)
			}
			if !strings.Contains(err.Error(), string(kind)) || !strings.Contains(err.Error(), "rule 0") {
				t.Fatalf("%s %s: message %q", kind, support, err)
			}
		}
	}
	sharedProductFactSupport = saved
	for kind, support := range saved {
		if err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(kind))); (err == nil) != (support == SharedFactSupported) {
			t.Fatalf("%s (%s) today: %v", kind, support, err)
		}
	}
}

// TestSharedPredicateAdmissionFirstOffendingRule: a mixed policy is refused
// with the first offending rule; within a rule its own predicates come before
// its exceptions.
func TestSharedPredicateAdmissionFirstOffendingRule(t *testing.T) {
	// No kind is "not yet" today: make the image kinds so for this test.
	withSharedFactSupport(t, SharedPredicateActorImage, SharedFactNotYet)
	withSharedFactSupport(t, SharedPredicateTargetImage, SharedFactNotYet)
	mixed := sharedPredicatePolicy(
		sharedPredicateRule(SharedPredicateActorUID),
		sharedPredicateRule(SharedPredicateActorRole),
		sharedPredicateRule(SharedPredicateTargetImage),
		sharedPredicateRule(SharedPredicateTargetArgv),
	)
	var e *SharedPredicateUnsupportedError
	if err := admitSharedProductPolicy(mixed); !errors.As(err, &e) || e.Rule != 2 || e.Kind != SharedPredicateTargetImage {
		t.Fatalf("mixed policy: %v", err)
	}
	// One rule using several kinds reports the first in enumeration order.
	yes := true
	both := sharedPredicateRule(SharedPredicateTargetArgv)
	both.Actor.FromImage = &yes
	if err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(SharedPredicateActorUID), both)); !errors.As(err, &e) || e.Rule != 1 || e.Kind != SharedPredicateActorImage {
		t.Fatalf("multi-kind rule: %v", err)
	}
	// Exceptions are walked too.
	deny := sharedPredicateRule(SharedPredicateActorUID)
	deny.Action = fullpolicy.Deny
	deny.Except = []fullpolicy.Exception{{Actor: fullpolicy.Actor{UID: []int64{1}}}, {Target: fullpolicy.Target{FromImage: &yes}}}
	err := admitSharedProductPolicy(sharedPredicatePolicy(deny))
	if !errors.As(err, &e) || e.Rule != 0 || e.Exception != 1 || e.Kind != SharedPredicateTargetImage || !strings.Contains(err.Error(), "rule 0 exception 1") {
		t.Fatalf("exception: %v", err)
	}
	if err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(SharedPredicateActorUID), sharedPredicateRule(SharedPredicateActorRole), sharedPredicateRule(SharedPredicateActorContainer))); err != nil {
		t.Fatalf("supported-only policy: %v", err)
	}
}

// TestSharedPredicateArgvRefusal: argv is permanently refused for the PoC,
// and says why; stdin (also under Argv) is a separate, supported kind.
func TestSharedPredicateArgvRefusal(t *testing.T) {
	prefix := sharedPredicateRule(SharedPredicateTargetArgv)
	prefix.Target.Argv = &fullpolicy.Argv{Prefix: []string{"--"}}
	for _, r := range []fullpolicy.Rule{sharedPredicateRule(SharedPredicateTargetArgv), prefix} {
		err := admitSharedProductPolicy(sharedPredicatePolicy(r))
		var e *SharedPredicateUnsupportedError
		if !errors.As(err, &e) || e.Kind != SharedPredicateTargetArgv || e.Support != SharedFactRefused {
			t.Fatalf("argv: %v", err)
		}
		for _, want := range []string{"target.argv", "refused for the PoC", "stock-kernel", "no authoritative argv fact"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("argv message %q lacks %q", err, want)
			}
		}
	}
	if err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(SharedPredicateTargetStdin))); err != nil {
		t.Fatalf("stdin: %v", err)
	}
	withSharedFactSupport(t, SharedPredicateActorImage, SharedFactNotYet)
	err := admitSharedProductPolicy(sharedPredicatePolicy(sharedPredicateRule(SharedPredicateActorImage)))
	if err == nil || strings.Contains(err.Error(), "stock-kernel") || !strings.Contains(err.Error(), "does not produce this fact yet") {
		t.Fatalf("image: %v", err)
	}
}

// TestSharedPublishRefusesUnsupportedPredicate: BindingSession.Publish
// refuses an unsupported predicate before compilation and before any
// publisher command; a supported policy still publishes.
func TestSharedPublishRefusesUnsupportedPredicate(t *testing.T) {
	withSharedFactSupport(t, SharedPredicateTargetImage, SharedFactNotYet)
	pub := newSharedFakePublisher()
	_, _, a, _ := sharedStartPublishingNode(t, pub)
	slot := a.Inspect().RouteSlot
	before, route := pub.publishes[slot], a.account.route.state
	for _, kind := range []SharedPredicateKind{SharedPredicateTargetImage, SharedPredicateTargetArgv} {
		source := sharedPredicatePolicy(sharedPredicateRule(SharedPredicateActorUID), sharedPredicateRule(kind))
		_, err := a.Publish(t.Context(), SharedBindingPolicy{Source: source, Container: "app"})
		var e *SharedPredicateUnsupportedError
		if !errors.As(err, &e) || e.Rule != 1 || e.Kind != kind {
			t.Fatalf("%s: %v", kind, err)
		}
		if pub.publishes[slot] != before || a.account.route.state != route {
			t.Fatalf("%s: refused policy reached the publisher", kind)
		}
	}
	source := sharedPredicatePolicy(sharedPredicateRule(SharedPredicateActorUID), sharedPredicateRule(SharedPredicateActorRole),
		sharedPredicateRule(SharedPredicateTargetPath), sharedPredicateRule(SharedPredicateActorAncestor), sharedPredicateRule(SharedPredicateTargetStdin))
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Source: source, Container: "app"}); err != nil {
		t.Fatal(err)
	}
}

// TestLegacyCompileUnaffectedByProductFacts: the legacy per-binding engine
// (fullpolicy.CompileKernel, Owner) does not use the product table.
func TestLegacyCompileUnaffectedByProductFacts(t *testing.T) {
	var rules []fullpolicy.Rule
	for _, kind := range []SharedPredicateKind{SharedPredicateActorPath, SharedPredicateActorAncestor, SharedPredicateTargetPath, SharedPredicateTargetFSType, SharedPredicateTargetStdin, SharedPredicateTargetArgv} {
		rules = append(rules, sharedPredicateRule(kind))
	}
	program, err := fullpolicy.CompileKernel([]fullpolicy.Policy{*sharedPredicatePolicy(rules...)}, 1, "app")
	if err != nil {
		t.Fatal(err)
	}
	if err := fullpolicy.ValidateKernelProgram(program); err != nil {
		t.Fatal(err)
	}
}

// sharedProductFactProducers pins, per supported kind, the source that
// produces its fact on the product path. A table flip to supported without a
// producer pin here fails TestSharedProductFactProducerPins.
var sharedProductFactProducers = map[SharedPredicateKind][]struct{ file, text string }{
	SharedPredicateActorRole: {
		// The product prepare frame runs the exec prepare reader...
		{"bpf/opaque_real_owner_child_candidate.bpf.c", "if (real_owner_prepare_reader_frame(&semantic, receipt, physical) == SE_OL_OK &&"},
		{"bpf/opaque_real_owner_child_candidate.bpf.c", "return se_owk_exec_prepare_reader(semantic, receipt, physical);"},
		// ...which fills the role facts from the exact exec history.
		{"../full/shared_pool_opaque_exec_prepare_candidate.h", "if (se_exec_fill_roles_preclassified(&work->history, &work->observation.facts)) {"},
	},
	SharedPredicateActorUID: {
		{"bpf/opaque_real_owner_child_candidate.bpf.c", "!BPF_CORE_READ_INTO(&effective_uid, cred, euid.val)) {\n" +
			"work->observation.facts.effective_uid = effective_uid;\nwork->observation.facts.uid_known = 1;"},
	},
	SharedPredicateActorContainer: {
		// Go stages the binding's container name in the snapshot metadata...
		{"shared_product_commander.go", "le.PutUint32(m[144:], uint32(len(f.container)))\ncopy(m[148:], f.container)"},
		// ...and the product view prepares the evaluator's container from it.
		{"bpf/opaque_real_owner_child_candidate.bpf.c", "return se_prepare_policy_view(&work->view, scope, snapshot, generation);"},
		{"../full/shared_policy_prepare.h", "(const struct fe_string *)&snapshot->metadata.container_length,"},
	},
	// G020 per-pass facts: every product object collects them, on every
	// evaluated pass (first and interpreter), into the WORK's facts.
	SharedPredicateActorPath: append(sharedPassFactsPins,
		pin{"../full/shared_pass_facts.h", "__u32 fault = se_pf_path(actor, &facts->actor_path, &cells);"}),
	SharedPredicateTargetPath: append(sharedPassFactsPins,
		pin{"../full/shared_pass_facts.h", "__u32 fault = rooted ? se_pf_path(target, &facts->target_path,\n&cells) :\n0;"}),
	SharedPredicateActorAncestor: append(sharedPassFactsPins,
		pin{"../full/shared_pass_facts.h", "fault = se_pf_path(exe, &facts->ancestors[i], &cells);"},
		pin{"../full/shared_pass_facts.h", "facts->ancestor_count = count;\nfacts->ancestors_complete = root || boundary;"},
		pin{"../full/shared_pass_facts.h", "se_pf_ancestors(task, facts, anchor);"}),
	SharedPredicateTargetFSType: append(sharedPassFactsPins,
		pin{"../full/shared_pass_facts.h", "struct full_fs_facts fs = SE_PF_FS(target);\nfacts->fs_mask = fs.mask & fs.known;\nfacts->fs_known = fs.known;"},
		pin{"bpf/opaque_real_owner_child_candidate.bpf.c", "#define SE_PF_FS(file) full_file_filesystem(file)"}),
	// G020 part 4: the classifier on the target and actor files against
	// the image identity of the snapshot record the exec's reader holds,
	// with the exact kernel's overlay layout.
	SharedPredicateTargetImage: append(sharedPassFactsPins, sharedImageFactPins...),
	SharedPredicateActorImage:  append(sharedPassFactsPins, sharedImageFactPins...),
	SharedPredicateTargetStdin: append(sharedPassFactsPins,
		pin{"../full/shared_pass_facts.h", "int stdin_pipe = SE_PF_STDIN(task);"},
		pin{"bpf/opaque_real_owner_child_candidate.bpf.c", "#define SE_PF_STDIN(task) full_stdin_pipe(task)"}),
}

type pin = struct{ file, text string }

var sharedImageFactPins = []pin{
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "(real_owner_prepare_image(&owner, receipt, &image, &anchor), 1) &&\n#endif\nreal_owner_pass_facts(bprm, &work->observation.facts, &anchor) >=\n0 &&\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\nreal_owner_pass_image(bprm, &work->observation.facts, image.handle,\nimage.dev, image.known) >= 0 &&"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "facts->target_image = real_owner_image_class(target, &image);"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "facts->actor_image = real_owner_image_class(actor, &image);\nbpf_put_file(actor);"},
	{"../full/shared_pass_facts.h", "facts->actor_image = -1;\nfacts->target_image = -1;"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "return se_image_classify(file, image->handle, image->dev, w);"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "image->handle = snapshot->metadata.image_handle;\nimage->dev = snapshot->metadata.image_dev;"},
	// The layout constant is installed per load (with the M7 load epoch);
	// without it a product object is refused at admission (M8).
	{"shared_host.go", "if constants, err := sharedImageOverlayConstants(); err == nil {\ngc.SetVar(operators.NativeConstantsKey, constants)\n}"},
	{"kernel_matrix.go", "return map[string]any{sharedImageOverlayLayoutConstant: layout, sharedVerdictLoadEpochConstant: epoch}, nil"},
	{"shared_host.go", "if err := validateSharedProductConstants(resources); err != nil {"},
}

// sharedPassFactsPins: the product composition carries the per-pass facts
// and the prepare frame collects them before the evaluation stage.
var sharedPassFactsPins = []pin{
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \\\n!defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE)\n#define ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE 1"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "real_owner_pass_facts(bprm, &work->observation.facts, &anchor) >=\n0 &&\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE"},
	{"bpf/opaque_real_owner_child_candidate.bpf.c", "return se_pass_facts_collect(bprm, facts, anchor);"},
	{"../full/shared_pass_facts.h", "se_pf_reset(facts);\nSE_PF_STAT(SE_PF_PASSES);"},
}

func TestSharedProductFactProducerPins(t *testing.T) {
	sources := map[string]string{}
	for kind, support := range SharedProductFactSupport() {
		pins := sharedProductFactProducers[kind]
		if support != SharedFactSupported {
			if len(pins) != 0 {
				t.Errorf("%s is %s but has producer pins: flip the table", kind, support)
			}
			continue
		}
		if len(pins) == 0 {
			t.Errorf("%s is supported without a kernel fact producer pin", kind)
		}
		for _, pin := range pins {
			src, ok := sources[pin.file]
			if !ok {
				raw, err := os.ReadFile(pin.file)
				if err != nil {
					t.Fatal(err)
				}
				src = squashSpace(string(raw))
				sources[pin.file] = src
			}
			if !strings.Contains(src, squashSpace(pin.text)) {
				t.Errorf("%s producer pin missing in %s: %q", kind, pin.file, pin.text)
			}
		}
	}
	for kind := range sharedProductFactProducers {
		if _, ok := sharedProductFactSupport[kind]; !ok {
			t.Errorf("producer pin for unknown kind %s", kind)
		}
	}
}

// withSharedFactSupport sets one kind's support for the test (restored at
// cleanup).
func withSharedFactSupport(t *testing.T, kind SharedPredicateKind, support SharedFactSupport) {
	t.Helper()
	saved := maps.Clone(sharedProductFactSupport)
	t.Cleanup(func() { sharedProductFactSupport = saved })
	sharedProductFactSupport = maps.Clone(saved)
	sharedProductFactSupport[kind] = support
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
