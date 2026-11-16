// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ocihandler

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestCheckBehavior(t *testing.T) {
	for _, tc := range []struct {
		name, metadata   string
		allow, wantError bool
	}{
		{"legacy", "name: legacy", false, false},
		{"observer", "behavior: observer", false, false},
		{"generator denied", "behavior: generator", false, true},
		{"mutator denied", "behavior: mutator", false, true},
		{"generator allowed", "behavior: generator", true, false},
		{"mutator allowed", "behavior: mutator", true, false},
		{"unknown", "behavior: other", true, true},
		{"empty", "behavior: ''", true, true},
		{"list", "behavior: [observer]", true, true},
		{"map", "behavior: {mode: observer}", true, true},
		{"number", "behavior: 1", true, true},
		{"bool", "behavior: false", true, true},
		{"null", "behavior: null", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := viper.New()
			config.SetConfigType("yaml")
			require.NoError(t, config.ReadConfig(strings.NewReader(tc.metadata)))
			err := checkBehaviorDeclaration([]byte(tc.metadata), tc.allow)
			if err == nil {
				err = checkBehavior(config, tc.allow)
			}
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
