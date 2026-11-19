// Copyright 2019-2026 The Inspektor Gadget authors
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

package tests

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestTraceFSSlowerDeltaPresence(t *testing.T) {
	var expected traceFSSlowerEvent
	require.NoError(t, json.Unmarshal([]byte(`{"delta_us":1,"file":"foo","op":"F_OPEN"}`), &expected))
	normalizeTraceFSSlowerEvent(&expected)

	for _, tt := range []struct {
		name      string
		output    string
		wantMatch bool
	}{
		{"zero", `{"delta_us":0,"file":"foo","op":"F_OPEN"}`, true},
		{"positive", `{"delta_us":42,"file":"foo","op":"F_OPEN"}`, true},
		{"missing", `{"file":"foo","op":"F_OPEN"}`, false},
		{"null", `{"delta_us":null,"file":"foo","op":"F_OPEN"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantMatch {
				match.MatchEntries(t, match.JSONMultiObjectMode, tt.output, normalizeTraceFSSlowerEvent, &expected)
				return
			}
			var actual traceFSSlowerEvent
			require.NoError(t, json.Unmarshal([]byte(tt.output), &actual))
			normalizeTraceFSSlowerEvent(&actual)
			// MatchEntries uses DeepEqual; absent durations must not match a present one.
			require.False(t, reflect.DeepEqual(&expected, &actual))
		})
	}
}
