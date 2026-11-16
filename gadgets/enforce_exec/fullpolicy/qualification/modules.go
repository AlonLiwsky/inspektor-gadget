// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"sort"
	"strings"
)

func moduleIdentity(m selectedModule) debug.Module {
	identity := debug.Module{Path: m.Path, Version: m.Version, Sum: m.Sum}
	if m.Replace != nil {
		r := moduleIdentity(*m.Replace)
		identity.Replace = &r
	}
	return identity
}

func checkRemoteIdentity(m debug.Module) error {
	if !remoteModulePath(m.Path) || !strings.HasPrefix(m.Version, "v") {
		return errors.New("MVS dependency is local or versionless")
	}
	if m.Replace != nil {
		if m.Replace.Replace != nil || !remoteModulePath(m.Replace.Path) || !strings.HasPrefix(m.Replace.Version, "v") {
			return errors.New("MVS replacement is local or versionless")
		}
	}
	return nil
}

func selectedModules(executable, root, mainPath string, env []string) ([]debug.Module, error) {
	data, err := commandOutput(executable, root, env, "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	seen := map[string]bool{}
	mainCount := 0
	var result []debug.Module
	for {
		var m selectedModule
		if err = decoder.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("invalid MVS module JSON")
		}
		if m.Path == "" || seen[m.Path] {
			return nil, errors.New("missing/duplicate selected module identity")
		}
		seen[m.Path] = true
		if m.Main {
			mainCount++
			if m.Path != mainPath || m.Replace != nil {
				return nil, errors.New("selected main module differs from command")
			}
			continue
		}
		identity := moduleIdentity(m)
		if err = checkRemoteIdentity(identity); err != nil {
			return nil, err
		}
		result = append(result, identity)
	}
	if mainCount != 1 {
		return nil, errors.New("MVS must contain exactly one consumer main module")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func checkLinkedModules(linked []*debug.Module, selected []debug.Module) error {
	inventory := make(map[string]debug.Module, len(selected))
	for _, m := range selected {
		if _, exists := inventory[m.Path]; exists {
			return errors.New("duplicate selected module identity")
		}
		if err := checkRemoteIdentity(m); err != nil {
			return err
		}
		inventory[m.Path] = m
	}
	seen := map[string]bool{}
	for _, m := range linked {
		if m == nil || seen[m.Path] {
			return errors.New("nil/duplicate linked module identity")
		}
		seen[m.Path] = true
		expected, ok := inventory[m.Path]
		if !ok {
			return errors.New("linked module absent from selected MVS")
		}
		if m.Version != expected.Version {
			return errors.New("linked module version differs from selected MVS")
		}
		if expected.Replace == nil {
			if m.Replace != nil || !strings.HasPrefix(expected.Sum, "h1:") || m.Sum != expected.Sum {
				return errors.New("linked module checksum/replacement differs from selected MVS")
			}
		} else {
			e := expected.Replace
			// Original sums are omitted for replaced modules in binary metadata.
			if m.Replace == nil || m.Replace.Replace != nil || !strings.HasPrefix(e.Sum, "h1:") || m.Replace.Path != e.Path || m.Replace.Version != e.Version || m.Replace.Sum != e.Sum {
				return errors.New("linked effective replacement differs from selected MVS")
			}
		}
	}
	return nil
}

func ptrModule(m debug.Module) *debug.Module { return &m }

func remoteModulePath(path string) bool {
	return strings.Contains(path, ".") && !strings.HasPrefix(path, ".") && !strings.HasPrefix(path, "/") && !strings.Contains(path, "\\")
}
