// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func workerRegularHash(root, name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != filepath.Clean(root) {
		return "", errors.New("noncanonical/symlink input root")
	}
	if filepath.IsAbs(name) || name == "" || filepath.ToSlash(filepath.Clean(name)) != name || name == ".." || strings.HasPrefix(name, "../") {
		return "", errors.New("noncanonical worker input")
	}
	current := root
	for _, component := range strings.Split(name, "/") {
		current = filepath.Join(current, component)
		st, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("symlink worker input")
		}
	}
	st, err := os.Lstat(current)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("nonregular worker input")
	}
	return fileHash(current)
}

func workerTree(inputs map[string]string, prefix, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in worker source tree")
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		h, err := workerRegularHash(root, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		inputs[prefix+"/"+filepath.ToSlash(rel)] = h
		return nil
	})
}

func snapshotWorker(goPath, root, target string) (workerSnapshot, error) {
	var s workerSnapshot
	consumer, err := snapshotConsumer(goPath, root, target)
	if err != nil {
		return s, err
	}
	s.Consumer = consumer
	s.RawProfile = map[string]string{}
	for name := range requiredEnvironment {
		s.RawProfile[name] = os.Getenv(name)
	}
	s.Inputs = map[string]string{}
	for name, value := range consumer.ToolHashes {
		s.Inputs["tools/"+name] = value
	}
	s.Inputs["module-graph"] = consumer.GraphHash
	for k, v := range consumer.Inputs {
		s.Inputs[k] = v
	}
	effective := consumer.Package.Module
	if effective.Replace != nil {
		effective = effective.Replace
	}
	selectedSum, err := workerRegularHash(effective.Dir, "go.sum")
	if err != nil {
		return s, err
	}
	s.Inputs["selected-module/go.sum"] = selectedSum
	runtimeDir := filepath.Join(filepath.Dir(consumer.Package.Dir), "fullruntime")
	if err = workerTree(s.Inputs, "fullruntime", runtimeDir); err != nil {
		return s, err
	}
	data, err := commandOutput(consumer.GoExecutable, consumer.Root, selectedEnvironment(consumer.GoExecutable), "list", "-deps", "-json", target)
	if err != nil {
		return s, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var p struct {
			ImportPath, Dir                                                                            string
			Standard                                                                                   bool
			Module                                                                                     *selectedModule
			GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SysoFiles, EmbedFiles []string
			Error                                                                                      *struct{ Err string }
		}
		if err = decoder.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return s, err
		}
		if p.Error != nil || p.ImportPath == "" || p.Dir == "" {
			return s, errors.New("incomplete selected import closure")
		}
		s.Packages = append(s.Packages, p.ImportPath)
		if p.ImportPath == workerRuntimePackage {
			found = true
			if p.Dir != runtimeDir {
				return s, errors.New("runtime/model selected source mismatch")
			}
		}
		prefix := "closure/" + p.ImportPath + "/"
		for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SysoFiles, p.EmbedFiles} {
			for _, name := range list {
				h, e := workerRegularHash(p.Dir, filepath.ToSlash(name))
				if e != nil {
					return s, e
				}
				s.Inputs[prefix+filepath.ToSlash(name)] = h
			}
		}
		if p.Module != nil {
			m := p.Module
			if m.Replace != nil {
				m = m.Replace
			}
			for _, name := range []string{"go.mod", "go.sum"} {
				if _, e := os.Lstat(filepath.Join(m.Dir, name)); errors.Is(e, os.ErrNotExist) && name == "go.sum" {
					continue
				}
				h, e := workerRegularHash(m.Dir, name)
				if e != nil {
					return s, e
				}
				s.Inputs["module/"+m.Path+"/"+name] = h
			}
		}
	}
	if !found {
		return s, errors.New("consumer import closure does not select fullruntime")
	}
	// Fixed proof files are captured even if compiler/linker packages are not
	// transitively linked into the consumer.
	proofFiles := append([]string(nil), workerStdlibProofFiles...)
	for name := range workerDependencySourcePins {
		if strings.HasPrefix(name, "toolchain/") {
			proofFiles = append(proofFiles, strings.TrimPrefix(name, "toolchain/"))
		}
	}
	for name := range workerProcSourcePins {
		if strings.HasPrefix(name, "toolchain/") {
			proofFiles = append(proofFiles, strings.TrimPrefix(name, "toolchain/"))
		}
	}
	for _, name := range proofFiles {
		h, e := workerRegularHash(consumer.Profile["GOROOT"], name)
		if e != nil {
			return s, e
		}
		s.Inputs["toolchain/"+name] = h
	}
	assemblyHeaders, err := workerAssemblyHeaderInputs(consumer.Profile["GOROOT"])
	if err != nil {
		return s, err
	}
	for name, hash := range assemblyHeaders {
		s.Inputs[name] = hash
	}
	sort.Strings(s.Packages)
	for _, name := range []string{"shared_worker_integration.go", "shared_operation_context.go", "proc_pin.go"} {
		if !workerDigest(s.Inputs["fullruntime/"+name]) {
			return s, fmt.Errorf("missing worker source %s", name)
		}
	}
	return s, nil
}
