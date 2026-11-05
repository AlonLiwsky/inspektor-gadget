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

package ebpfoperator

import "testing"

func TestPartialStartCleanupIsIdempotent(t *testing.T) {
	i := &ebpfInstance{done: make(chan struct{}), bpfOperator: &ebpfOperator{}}
	for n := 0; n < 2; n++ {
		if err := i.PreStop(nil); err != nil {
			t.Fatal(err)
		}
		if err := i.Stop(nil); err != nil {
			t.Fatal(err)
		}
		if err := i.Close(nil); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-i.done:
	default:
		t.Fatal("stop signal remains open")
	}
}
