// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// This models only the transport fault boundary. It does not attest candidate
// activation, accepted history, or actual BPF command semantics.
type sharedCommandFaultTransport struct {
	afterRun                  func()
	command                   sharedCommandWire
	receipt                   sharedReceiptWire
	writes, runs, reads       int
	writeErr, runErr, readErr error
	result                    uint32
	refuse                    bool
}

func (f *sharedCommandFaultTransport) writeSharedCommand(c sharedCommandWire) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.command = c
	return nil
}

func (f *sharedCommandFaultTransport) runSharedCommand() (uint32, error) {
	f.runs++
	f.receipt = sharedReceiptWire{NodeCookie: f.command.NodeCookie, Sequence: f.command.Sequence, Operation: f.command.Operation, Serial: 19, Value: 1}
	if f.refuse {
		f.receipt.Status = 1
	}
	if f.afterRun != nil {
		f.afterRun()
	}
	return f.result, f.runErr
}

func (f *sharedCommandFaultTransport) readSharedReceipt() (sharedReceiptWire, error) {
	f.reads++
	return f.receipt, f.readErr
}

func TestSharedCandidateTransportLostAcknowledgement(t *testing.T) {
	for _, operation := range []uint32{8, 9, 10, 11, 12, 13} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
			f := &sharedCommandFaultTransport{readErr: errors.New("lost receipt")}
			request := sharedCommandWire{Operation: operation, Binding: 1, Record: 1, Scope: 7, Serial: 18}
			if _, err := c.callCommand(request, f); err == nil {
				t.Fatal("lost receipt accepted")
			}
			if f.runs != 1 || c.pending == nil {
				t.Fatal("unknown execution lost ownership")
			}
			other := request
			other.Serial++
			if _, err := c.callCommand(other, f); err == nil {
				t.Fatal("different command overwrote unresolved receipt")
			}
			if f.writes != 1 || f.runs != 1 {
				t.Fatal("pending command replayed or overwritten")
			}
			f.readErr = nil
			receipt, err := c.callCommand(request, f)
			if err != nil || receipt.Serial != 19 || c.pending != nil {
				t.Fatalf("reconciliation: %+v %v", receipt, err)
			}
			if f.writes != 1 || f.runs != 1 || c.sequence != 1 {
				t.Fatal("reconciliation re-executed non-idempotent command")
			}
		})
	}
}

func TestSharedCandidateTransportRunFailureKeepsReceipt(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{runErr: errors.New("run result unavailable")}
	request := sharedCommandWire{Operation: 8, Scope: 7, Serial: 18}
	if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
		t.Fatal("run failure discarded")
	}
	if _, err := c.callCommand(request, f); err != nil {
		t.Fatal(err)
	}
	if f.runs != 1 || f.writes != 1 || c.pending != nil {
		t.Fatal("successful receipt replayed")
	}
}

func TestSharedCandidateTransportRefusalAndIdentity(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{readErr: errors.New("read unavailable"), refuse: true, result: 1}
	request := sharedCommandWire{Operation: 11, Scope: 7, Serial: 18}
	if _, err := c.callCommand(request, f); err == nil {
		t.Fatal("missing receipt accepted")
	}
	f.readErr = nil
	saved := f.receipt
	for _, mutate := range []func(*sharedReceiptWire){
		func(r *sharedReceiptWire) { r.Sequence++ }, func(r *sharedReceiptWire) { r.NodeCookie++ },
		func(r *sharedReceiptWire) { r.Operation++ }, func(r *sharedReceiptWire) { r.Reserved = 1 },
		func(r *sharedReceiptWire) { r.Status = 2 },
	} {
		f.receipt = saved
		mutate(&f.receipt)
		if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
			t.Fatal("foreign/malformed receipt resolved ownership")
		}
	}
	f.receipt = saved
	if _, err := c.callCommand(request, f); err == nil || c.pending != nil {
		t.Fatal("known refusal not resolved")
	}
	if f.runs != 1 || f.writes != 1 {
		t.Fatal("refused command repeated")
	}
}

func TestSharedCandidateTransportWriteFailureNeverRan(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{writeErr: errors.New("write failed")}
	if _, err := c.callCommand(sharedCommandWire{Operation: 8}, f); err == nil {
		t.Fatal("write failure ignored")
	}
	if c.pending != nil || f.runs != 0 {
		t.Fatal("unexecuted command marked as unknown execution")
	}
}

func TestSharedCandidateTransportContradictionRemainsPending(t *testing.T) {
	for _, result := range []uint32{1, 2} {
		c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
		f := &sharedCommandFaultTransport{result: result}
		request := sharedCommandWire{Operation: 8, Scope: 7, Serial: 18}
		if _, err := c.callCommand(request, f); err == nil || c.pending == nil {
			t.Fatal("contradictory result accepted")
		}
		if _, err := c.callCommand(request, f); err == nil || f.runs != 1 {
			t.Fatal("contradictory result retried or forgotten")
		}
	}
}

func TestSharedCandidateTransportBindingScopeAndSequenceBoundary(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}, sequence: math.MaxUint64 - 2}
	f := &sharedCommandFaultTransport{readErr: errors.New("read failed")}
	request := sharedCommandWire{Operation: sharedBindingOpen, CgroupIdentity: 42}
	if _, err := c.callCommand(request, f); err == nil {
		t.Fatal("missing receipt accepted")
	}
	if f.command.Scope != math.MaxUint64-1 || f.command.Scope != f.command.Sequence || f.command.NodeCookie != 11 || f.command.Nonce != 22 {
		t.Fatal("transport identity not derived from frozen node/sequence")
	}
	f.readErr = nil
	if _, err := c.callCommand(request, f); err != nil {
		t.Fatalf("exhausted sequence prevented reconciliation: %v", err)
	}
	if _, err := c.callCommand(request, f); err == nil || f.runs != 1 {
		t.Fatal("exhausted sequence executed")
	}
}

func TestSharedCandidateCanceledCallRetainsCompletedReceipt(t *testing.T) {
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}, thread: thread}
	t.Cleanup(func() {
		if err := c.close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &sharedCommandFaultTransport{afterRun: cancel}
	request := sharedCommandWire{Operation: 8, Binding: 1, Record: 1, Scope: 7, Serial: 18}
	receipt, err := c.callWithTransport(ctx, request, f)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not reported: %v", err)
	}
	if receipt.NodeCookie != 11 || receipt.Sequence != 1 || receipt.Operation != request.Operation || receipt.Status != 0 || receipt.Serial != 19 || receipt.Reserved != 0 {
		t.Fatalf("completed receipt lost on canceled joined call: %+v", receipt)
	}
	if c.pending != nil || f.runs != 1 || f.writes != 1 {
		t.Fatal("completed command replayed or left ambiguous")
	}
	// Do not retry on err: the receipt proves this operation completed. A fresh
	// call after pending cleared would be a NEW command, not reconciliation.
}

// This reuses the actual authenticated command body and reader primitives. It
// proves candidate operations preserve a held active record, not root/factual
// qualification, real BPF concurrency or native publication integration.
func TestSharedCandidateCommandsKeepActiveReader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	source := `#define main original_fixture_main
#include "shared_control.c"
#undef main
int main(void) {
 command=(struct se_control_command){.scope=1};
 assert(!call(SE_BINDING_OPEN));
 command.object=1;
 command.attempt=99;
 command.count=1;
 assert(!call(SE_OBJECT_BEGIN));
 command.generation=receipt.generation;
 assert(!call(SE_OBJECT_WRITE));
 command.execution_class=CANDIDATE_TEST_CLASS;
 assert(!call(SE_OBJECT_FINALIZE));
 command.metadata=(struct se_snapshot_metadata){.root_epochs={1},.policy_uids={1},.container_length=1,.container={'c'},.role_writers=1};
 command.handles[0]=(struct se_pin_ticket){.object_slot=1,.object_generation=1};
 command.generation=bindings[0].state.generation;
 command.serial=bindings[0].state.next_serial;
 command.record=0;
 command.count=1;
 command.execution_class=CANDIDATE_TEST_CLASS;
 assert(!call(SE_SNAPSHOT_PREPARE));
 command.serial=receipt.serial;
 assert(!call(SE_SNAPSHOT_PIN));
 assert(!call(SE_SNAPSHOT_SEAL));
 bpf_spin_lock(&routes[0].lock);
 assert(!se_route_commit_preflight_locked(&routes[0],&bindings[0].state,0,command.serial,routes[0].admission_serial));
 se_route_commit_publish_locked(&routes[0],&bindings[0].state,0);
 struct se_reader_owner owner={};
 struct se_reader_token token={};
 assert(!se_reader_acquire_locked(&bindings[0].state,1,99,&owner,&token));
 bpf_spin_unlock(&routes[0].lock);
 struct se_snapshot active=bindings[0].state.records[0];
 struct se_route_anchor route=routes[0];
 __u64 generation=bindings[0].state.generation;
 __u64 admission=bindings[0].state.admission_serial;
 __u64 active_serial=bindings[0].state.active_serial;
 assert(active.claims==1 && objects[1].state.pins==1);
 command.record=1;
 command.generation=generation-1;
 command.serial=bindings[0].state.next_serial;
 assert(call(SE_SNAPSHOT_PREPARE)); /* stale revision refused, no drain */
 assert(bindings[0].state.records[1].phase==SE_SNAPSHOT_FREE);
 command.generation=generation;
 assert(!call(SE_SNAPSHOT_PREPARE));
 command.serial=receipt.serial;
 assert(!call(SE_SNAPSHOT_PIN));
 assert(!call(SE_SNAPSHOT_SEAL));
 assert(objects[1].state.pins==2);
 assert(!memcmp(&active,&bindings[0].state.records[0],sizeof(active)));
 assert(!memcmp(&route,&routes[0],sizeof(route)));
 /* Refuse this prepared candidate: only its own tickets may be released. */
 assert(!call(SE_SNAPSHOT_ABORT));
 assert(!call(SE_SNAPSHOT_RELEASE));
 assert(!call(SE_SNAPSHOT_RELEASE)); /* exact ticket release replay */
 assert(objects[1].state.pins==1);
 assert(!call(SE_SNAPSHOT_RECLAIM));
 assert(call(SE_SNAPSHOT_RECLAIM)); /* stale reclaim must not touch active */
 assert(!memcmp(&active,&bindings[0].state.records[0],sizeof(active)));
 assert(!memcmp(&route,&routes[0],sizeof(route)));
 assert(bindings[0].state.generation==generation);
 assert(bindings[0].state.admission_serial==admission);
 assert(bindings[0].state.active_serial==active_serial);
 assert(bindings[0].state.active_record==0 && owner.owned);
 bpf_spin_lock(&routes[0].lock);
 assert(!se_reader_release_locked(&bindings[0].state,&owner,&token));
 bpf_spin_unlock(&routes[0].lock);
 assert(!owner.owned && !bindings[0].state.records[0].claims);
 puts("candidate stale/refusal cleanup preserves held active reader, metadata and admission");
 return 0;
}
`
	for _, class := range []int{1, 2} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "candidate.c")
			binary := filepath.Join(dir, "candidate")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", fmt.Sprintf("-DCANDIDATE_TEST_CLASS=%d", class), "-iquote", root, "-iquote", fixtures, path, "-o", binary).CombinedOutput()
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, out)
			}
			out, err = exec.Command(binary).CombinedOutput()
			if err != nil {
				t.Fatalf("candidate: %v\n%s", err, out)
			}
			t.Log(string(out))
		})
	}
}

func TestSharedCandidateMetadataMatchesActualSeal(t *testing.T) {
	var generated strings.Builder
	for seed := 0; seed < 16; seed++ {
		policies := make([]fullpolicy.Policy, 8)
		refs := make([]fullpolicy.SharedPolicyRef, 8)
		for i := range policies {
			p := fullpolicy.Policy{ID: fmt.Sprintf("policy-%d", (i*5)%8), Revision: "r", RootRole: "root", Mode: fullpolicy.Audit}
			if seed != 0 && (i+seed)%4 == 0 {
				p.Mode = fullpolicy.Enforce
			}
			if (i+seed)%3 == 0 {
				p.Default = fullpolicy.Deny
			}
			r := fullpolicy.Rule{Name: "r", Action: fullpolicy.Allow}
			if seed != 0 && (i+seed)%5 == 0 {
				r.Mode = fullpolicy.Enforce
			} else if (i+seed)%2 == 0 {
				r.Mode = fullpolicy.Audit
			}
			if (i+seed)%3 != 1 {
				r.Actor.Role = []string{"root"}
			}
			if (i+seed)%4 == 0 {
				r.Target.SetRole = "next"
			} else if (i+seed)%2 == 0 {
				r.Action = fullpolicy.Deny
			}
			p.Rules = []fullpolicy.Rule{r}
			policies[i] = p
			object, err := fullpolicy.CompileSharedPolicy(p)
			if err != nil {
				t.Fatal(err)
			}
			refs[(i+seed)%8] = fullpolicy.SharedPolicyRef{Object: object, RootEpoch: 1}
		}
		snapshot, err := fullpolicy.NewSharedSnapshot(7, 2, "app", refs)
		if err != nil {
			t.Fatal(err)
		}
		summary, err := snapshot.ExecutionMetadata()
		if err != nil {
			t.Fatal(err)
		}
		if seed == 0 && (summary.ExecutionClass != 1 || summary.RequiredKnown != 0) {
			t.Fatal("audit-only dependency gained strict requirement")
		}
		program, err := fullpolicy.CompileKernel(policies, 2, "app")
		if err != nil {
			t.Fatal(err)
		}
		var required, writers uint32
		for i := uint32(0); i < 8; i++ {
			policy, err := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase+i])
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for j, ref := range refs {
				if ref.Object.UID() == policy.UID {
					found = true
					if summary.RequiredKnown&(1<<j) != 0 {
						required |= 1 << i
					}
					if summary.RoleWriters&(1<<j) != 0 {
						writers |= 1 << i
					}
				}
			}
			if !found {
				t.Fatal("missing compiled UID")
			}
		}
		fmt.Fprintf(&generated, "/* shared metadata seed=%d */\n{static const unsigned char image[][288]={\n", seed)
		for _, blob := range program.Entries {
			generated.WriteString("{")
			for _, b := range blob {
				fmt.Fprintf(&generated, "%d,", b)
			}
			generated.WriteString("},\n")
		}
		generated.WriteString("};\nmemset(cells,0,sizeof(cells));memset(&work,0,sizeof(work));\n")
		generated.WriteString("dispatch=(struct eo_dispatch){.scope_state=EO_SCOPE_ACTIVE,.session_cookie=7,.cgroup=42,.serial=1,.active={.generation=1,.execution_class=1,.policy_count=1}};\n")
		fmt.Fprintf(&generated, "assert(!eo_candidate_begin_locked(&dispatch,7,2,%d));\n", len(program.Entries))
		fmt.Fprintf(&generated, "for(__u32 key=0;key<%d;key++){struct eo_candidate_input input={.request={.session_cookie=7,.attempt=2,.entries=%d,.index=key,.bank=1}};memcpy(input.data,image[key],288);assert(!eo_candidate_write_cell(&dispatch,&input.request,input.data,&cells[1][key]));}\n", len(program.Entries), len(program.Entries))
		fmt.Fprintf(&generated, "assert(eo_seal_candidate(&dispatch,7,2)==EO_OK);assert(dispatch.candidate.required_known_mask==%d);assert(dispatch.candidate.sealed_role_writer_mask==%d);assert(dispatch.candidate.sealed_class==%d);assert(!work.busy&&!work.reader.owned&&!dispatch.authority_readers&&!dispatch.bank_readers[1]);}\n", required, writers, summary.ExecutionClass)
	}
	runOwnerSealFixture(t, generated.String())
}
