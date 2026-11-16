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

package uprobetracer

import "testing"

func TestUnsupportedProgTypeDiagnostics(t *testing.T) {
	tr := &Tracer[struct{}]{}
	const invalid = ProgType(42)

	// Validation precedes the nil-program check and must not mutate attachment state.
	if err := tr.AttachProg("probe", invalid, "/bin/sh:main", nil); err == nil || err.Error() != "unsupported uprobe prog type: 42" {
		t.Fatalf("AttachProg invalid type: got %v", err)
	}
	if tr.prog != nil || tr.progName != "" || tr.progType != ProgUprobe {
		t.Fatalf("AttachProg invalid type changed attachment state: %+v", tr)
	}

	tr.progType = invalid
	probe, err := tr.bindProbe(nil, nil)
	if probe != nil || err == nil || err.Error() != "attaching to inode: unsupported prog type: 42" {
		t.Fatalf("bindProbe invalid type: probe=%v, err=%v", probe, err)
	}
}
