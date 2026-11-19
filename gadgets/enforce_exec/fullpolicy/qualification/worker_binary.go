// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"runtime/debug"
	"strconv"
	"strings"
)

// Worker BUILD emits this exact flag string itself. Unlike the legacy syntax
// validator it allows precisely one computed carrier assignment, never a broad
// -X allowlist. Version overrides are not emitted by this controlled recipe.
func checkWorkerLinkerFlags(raw, carrier string) error {
	if !validWorkerCarrier(carrier) || raw != "-X "+workerCarrierTarget+"="+carrier {
		return errors.New("worker linker flags differ from exact computed assignment")
	}
	return nil
}

func checkWorkerBinary(info *debug.BuildInfo, s workerSnapshot, carrier string) error {
	if info == nil {
		return errors.New("missing worker binary build info")
	}
	copyInfo := *info
	copyInfo.Settings = append([]debug.BuildSetting(nil), info.Settings...)
	seen := false
	for i, setting := range copyInfo.Settings {
		if setting.Key == "-ldflags" {
			if seen {
				return errors.New("duplicate worker linker settings")
			}
			seen = true
			if err := checkWorkerLinkerFlags(setting.Value, carrier); err != nil {
				return err
			}
			// Validate all remaining syntax-independent profile/module rules without
			// changing the existing syntax allowlist or the original binary evidence.
			copyInfo.Settings[i].Value = ""
		}
	}
	if !seen {
		return errors.New("missing worker carrier linker assignment")
	}
	if err := checkBinaryInfo(s.Consumer.Modules, &copyInfo, *s.Consumer.Package.Module, s.Consumer.Profile); err != nil {
		return err
	}
	return checkBinaryCommand(info, s.Consumer.Command)
}

func validWorkerCarrier(carrier string) bool {
	if len(carrier) != 366 || !strings.HasPrefix(carrier, "IGW100010001") || (carrier[12:14] != "01" && carrier[12:14] != "02") {
		return false
	}
	for i := range 5 {
		if !workerDigest(carrier[14+i*64 : 14+(i+1)*64]) {
			return false
		}
	}
	for _, part := range []string{carrier[334:350], carrier[350:366]} {
		for _, c := range part {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	b, err := strconv.ParseUint(carrier[334:350], 16, 64)
	if err != nil || b == 0 {
		return false
	}
	t, err := strconv.ParseUint(carrier[350:366], 16, 64)
	return err == nil && t != 0 && t <= ^uint64(0)-b
}
