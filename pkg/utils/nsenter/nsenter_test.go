// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nsenter

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeSetns replaces the setns seam. The target is the test's own process,
// whose namespace files are readable without root, and no real setns(2)
// happens. The first call is the enter, the second the restore.
func fakeSetns(t *testing.T, enterErr, restoreErr error) (calls *[]int, exits *[]bool) {
	t.Helper()
	calls, exits = new([]int), new([]bool)
	origSetns, origHook := setns, testHookThreadExit
	t.Cleanup(func() { setns, testHookThreadExit = origSetns, origHook })
	setns = func(fd, nstype int) error {
		*calls = append(*calls, nstype)
		if len(*calls) == 1 {
			return enterErr
		}
		return restoreErr
	}
	testHookThreadExit = func(locked bool) { *exits = append(*exits, locked) }
	return calls, exits
}

var enters = map[string]struct {
	fn     func(int, func() error) error
	nsType int
}{
	"net":    {NetnsEnter, unix.CLONE_NEWNET},
	"cgroup": {CgroupnsEnter, unix.CLONE_NEWCGROUP},
}

func TestEnter(t *testing.T) {
	errCallback := errors.New("callback failed")
	errEnter := errors.New("enter failed")
	errRestore := errors.New("restore failed")

	tests := map[string]struct {
		callbackErr, enterErr, restoreErr error
		wantCalls                         int
		wantRan                           bool
		wantIs                            []error
		wantNotIs                         []error
		wantLocked                        bool
	}{
		"success": {wantCalls: 2, wantRan: true},
		"callback error": {
			callbackErr: errCallback, wantCalls: 2, wantRan: true,
			wantIs: []error{errCallback}, wantNotIs: []error{ErrRestoreNamespace},
		},
		"enter failure": {
			enterErr: errEnter, wantCalls: 1,
			wantIs: []error{errEnter}, wantNotIs: []error{ErrRestoreNamespace},
		},
		"restore failure": {
			restoreErr: errRestore, wantCalls: 2, wantRan: true,
			wantIs: []error{ErrRestoreNamespace, errRestore}, wantLocked: true,
		},
		"callback and restore failure": {
			callbackErr: errCallback, restoreErr: errRestore, wantCalls: 2, wantRan: true,
			wantIs: []error{errCallback, ErrRestoreNamespace, errRestore}, wantLocked: true,
		},
	}
	for kind, e := range enters {
		for name, tc := range tests {
			t.Run(kind+"/"+name, func(t *testing.T) {
				calls, exits := fakeSetns(t, tc.enterErr, tc.restoreErr)
				ran := false
				err := e.fn(os.Getpid(), func() error {
					ran = true
					return tc.callbackErr
				})

				if ran != tc.wantRan {
					t.Errorf("callback ran = %v, want %v", ran, tc.wantRan)
				}
				if len(*calls) != tc.wantCalls {
					t.Fatalf("setns calls = %d, want %d", len(*calls), tc.wantCalls)
				}
				for _, nstype := range *calls {
					if nstype != e.nsType {
						t.Errorf("setns nstype = %#x, want %#x", nstype, e.nsType)
					}
				}
				if len(tc.wantIs) == 0 && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for _, want := range tc.wantIs {
					if !errors.Is(err, want) {
						t.Errorf("error %v does not wrap %v", err, want)
					}
				}
				for _, notWant := range tc.wantNotIs {
					if errors.Is(err, notWant) {
						t.Errorf("error %v unexpectedly wraps %v", err, notWant)
					}
				}
				// The namespace goroutine must have exited before the call
				// returned, still locked exactly when the restore failed, so
				// the runtime discards its thread instead of reusing it.
				if len(*exits) != 1 || (*exits)[0] != tc.wantLocked {
					t.Errorf("thread exits (locked) = %v, want [%v]", *exits, tc.wantLocked)
				}
			})
		}
	}
}

func TestEnterPidZeroRunsInline(t *testing.T) {
	for kind, e := range enters {
		t.Run(kind, func(t *testing.T) {
			calls, exits := fakeSetns(t, nil, nil)
			ran := false
			if err := e.fn(0, func() error { ran = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if !ran || len(*calls) != 0 || len(*exits) != 0 {
				t.Errorf("ran=%v setns calls=%d thread exits=%d, want true 0 0", ran, len(*calls), len(*exits))
			}
		})
	}
}

func TestEnterPanicRestoresAndRepanics(t *testing.T) {
	for kind, e := range enters {
		t.Run(kind, func(t *testing.T) {
			calls, exits := fakeSetns(t, nil, nil)
			defer func() {
				if v := recover(); v != "boom" {
					t.Errorf("recovered %v, want boom", v)
				}
				if len(*calls) != 2 || len(*exits) != 1 || (*exits)[0] {
					t.Errorf("setns calls=%d thread exits=%v, want 2 [false]", len(*calls), *exits)
				}
			}()
			_ = e.fn(os.Getpid(), func() error { panic("boom") })
		})
	}
}

func TestEnterGoexitKeepsThreadLocked(t *testing.T) {
	for kind, e := range enters {
		t.Run(kind, func(t *testing.T) {
			calls, exits := fakeSetns(t, nil, nil)
			err := e.fn(os.Getpid(), func() error {
				runtime.Goexit()
				return nil
			})
			if !errors.Is(err, ErrCallbackExited) {
				t.Errorf("error = %v, want ErrCallbackExited", err)
			}
			// No restore was attempted, so the thread must exit locked.
			if len(*calls) != 1 || len(*exits) != 1 || !(*exits)[0] {
				t.Errorf("setns calls=%d thread exits (locked)=%v, want 1 [true]", len(*calls), *exits)
			}
		})
	}
}
