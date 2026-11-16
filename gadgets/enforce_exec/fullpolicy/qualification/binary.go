// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
)

// This is a producer-specific allowlist, not permission to override arbitrary
// SDK/model strings with -X. Raw linker flags remain in the binary's record.
func checkLinkerFlags(raw string) error {
	var fields []string
	for raw != "" {
		raw = strings.TrimLeft(raw, " \t\r\n")
		if raw == "" {
			break
		}
		if raw[0] == '\'' || raw[0] == '"' {
			quote := raw[0]
			end := strings.IndexByte(raw[1:], quote)
			if end < 0 {
				return errors.New("unterminated linker flag quote")
			}
			fields = append(fields, raw[1:end+1])
			raw = raw[end+2:]
			if raw != "" && !strings.ContainsRune(" \t\r\n", rune(raw[0])) {
				return errors.New("ambiguous quoted linker flag")
			}
		} else {
			end := strings.IndexAny(raw, " \t\r\n")
			if end < 0 {
				end = len(raw)
			}
			field := raw[:end]
			if strings.ContainsAny(field, "\"'\\") {
				return errors.New("unsupported linker flag quoting")
			}
			fields = append(fields, field)
			raw = raw[end:]
		}
	}
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-s", "-w":
		case "-X":
			i++
			if i >= len(fields) {
				return errors.New("missing -X assignment")
			}
			name, _, ok := strings.Cut(fields[i], "=")
			if !ok {
				return errors.New("invalid -X assignment")
			}
			switch name {
			case "github.com/armosec/private-node-agent/pkg/version.Version", "github.com/armosec/private-node-agent/pkg/version.Commit", "github.com/armosec/private-node-agent/pkg/version.BuildTime":
			default:
				return fmt.Errorf("unsupported linker override %q", name)
			}
		default:
			return fmt.Errorf("unsupported linker flag %q", fields[i])
		}
	}
	return nil
}

func checkBinaryInfo(inventory []debug.Module, info *debug.BuildInfo, selected selectedModule, profile map[string]string) error {
	if info == nil || info.GoVersion != "go1.27.3" {
		return errors.New("binary Go version differs from audited profile")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		if _, ok := settings[s.Key]; ok {
			return fmt.Errorf("duplicate binary setting %s", s.Key)
		}
		settings[s.Key] = s.Value
		switch s.Key {
		case "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED", "GOEXPERIMENT", "-buildmode", "-compiler":
		case "-ldflags":
			if err := checkLinkerFlags(s.Value); err != nil {
				return err
			}
		case "-trimpath":
			return errors.New("trimpath hides linker flags; trusted build descriptor required")
		case "DefaultGODEBUG": // Compared to selected main by checkBinaryCommand.
		case "vcs", "vcs.revision", "vcs.time", "vcs.modified":
		case "GOFIPS140":
			if s.Value != "off" {
				return errors.New("unsupported binary FIPS profile")
			}
		default:
			return fmt.Errorf("unsupported binary setting %q", s.Key)
		}
	}
	for k, want := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-buildmode": "exe", "-compiler": "gc"} {
		if settings[k] != want {
			return fmt.Errorf("missing/incompatible binary setting %s=%q", k, settings[k])
		}
	}
	if settings["GOEXPERIMENT"] != profile["GOEXPERIMENT"] {
		return errors.New("binary raw GOEXPERIMENT differs from tested profile")
	}
	if err := checkLinkedModules(info.Deps, inventory); err != nil {
		return err
	}
	for _, m := range info.Deps {
		if m.Path == gadgetModule {
			// Tie the package-specific selection to the complete MVS check.
			return checkLinkedModules([]*debug.Module{m}, []debug.Module{moduleIdentity(selected)})
		}
	}
	return errors.New("binary must contain the selected IG dependency")
}
