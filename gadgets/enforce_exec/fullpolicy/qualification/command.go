// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

type consumerCommand struct {
	DefaultGODEBUG     string            `json:"default_godebug"`
	ImplicitPGOAbsent  bool              `json:"implicit_pgo_absent"`
	Target             string            `json:"target"`
	ImportPath         string            `json:"import_path"`
	MainModule         string            `json:"main_module"`
	Files              map[string]string `json:"selected_files"`
	IdentityLimitation string            `json:"identity_limitation"`
}

func checkCommandTarget(target string) error {
	if strings.HasSuffix(target, ".go") {
		return errors.New("file targets have no representable main-module identity; use a module-associated main package such as ./cmd")
	}
	if !strings.HasPrefix(target, "./") || strings.ContainsAny(target, " \t\n\r\\") || strings.Contains(target, "...") || filepath.Clean(target) == ".." || strings.HasPrefix(filepath.Clean(target), "../") {
		return errors.New("-consumer-command requires one module-relative ./package target")
	}
	return nil
}

func snapshotCommand(executable, root, target string, env []string) (consumerCommand, error) {
	c := consumerCommand{Target: target, Files: map[string]string{}, IdentityLimitation: "BuildInfo identifies the main package, not authenticated build execution or individual linked packages"}
	if err := checkCommandTarget(target); err != nil {
		return c, err
	}
	data, err := commandOutput(executable, root, env, "list", "-m", "-json")
	if err != nil {
		return c, err
	}
	var main selectedModule
	if err = json.Unmarshal(data, &main); err != nil {
		return c, err
	}
	if !main.Main || main.Path == "" || main.Dir != root {
		return c, errors.New("unexpected consumer main module")
	}
	c.MainModule = main.Path
	data, err = commandOutput(executable, root, env, "list", "-json", target)
	if err != nil {
		return c, err
	}
	var p struct {
		DefaultGODEBUG                                                                             string
		Name, ImportPath, Dir                                                                      string
		GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SysoFiles, EmbedFiles []string
	}
	if err = json.Unmarshal(data, &p); err != nil {
		return c, err
	}
	if p.Name != "main" || len(p.GoFiles) == 0 {
		return c, errors.New("consumer command must select a main package")
	}
	c.ImportPath = p.ImportPath
	c.DefaultGODEBUG = p.DefaultGODEBUG
	if _, err := os.Lstat(filepath.Join(p.Dir, "default.pgo")); !errors.Is(err, os.ErrNotExist) {
		return c, errors.New("implicit default.pgo is unsupported for syntax evidence")
	}
	c.ImplicitPGOAbsent = true
	if p.ImportPath == "command-line-arguments" || (p.ImportPath != main.Path && !strings.HasPrefix(p.ImportPath, main.Path+"/")) {
		return c, errors.New("command must have a module-associated main package identity")
	}
	for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SysoFiles, p.EmbedFiles} {
		for _, name := range list {
			path := filepath.Join(p.Dir, name)
			resolved, e := filepath.EvalSymlinks(path)
			if e != nil {
				return c, e
			}
			relative, e := filepath.Rel(root, resolved)
			if e != nil {
				return c, e
			}
			if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return c, errors.New("command source escapes consumer root")
			}
			h, e := fileHash(resolved)
			if e != nil {
				return c, e
			}
			c.Files[filepath.ToSlash(relative)] = h
		}
	}
	return c, nil
}

func checkBinaryCommand(info *debug.BuildInfo, c consumerCommand) error {
	for _, setting := range info.Settings {
		if setting.Key == "DefaultGODEBUG" && setting.Value != c.DefaultGODEBUG {
			return errors.New("binary default GODEBUG differs from selected command")
		}
	}
	observed := ""
	for _, setting := range info.Settings {
		if setting.Key == "DefaultGODEBUG" {
			observed = setting.Value
		}
	}
	if observed != c.DefaultGODEBUG {
		return errors.New("binary default GODEBUG missing/mismatched")
	}
	if info.Main.Path != c.MainModule || info.Main.Version == "" || info.Main.Sum != "" || info.Main.Replace != nil || info.Path != c.ImportPath {
		return fmt.Errorf("binary main module/package %q/%q differs from selected %q/%q", info.Main.Path, info.Path, c.MainModule, c.ImportPath)
	}
	return nil
}
