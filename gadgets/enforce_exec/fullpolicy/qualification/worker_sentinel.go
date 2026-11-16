// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	workerSentinelPackage = "github.com/cilium/ebpf"
	workerSentinelName    = "ErrNotSupported"
)

// This is a scoped semantic result, not a complete nonmutation certificate.
// OpaqueInputs require separate approved-source review for assembly/unsafe
// behavior. In particular, this check must not on its own enable a carrier.
type workerSentinelEvidence struct {
	Scope           string            `json:"scope"`
	InputsSHA256    string            `json:"inputs_sha256"`
	ExportSHA256    map[string]string `json:"export_sha256"`
	CheckedPackages []string          `json:"type_checked_packages"`
	OpaqueInputs    map[string]string `json:"opaque_inputs_requiring_review"`
}

type workerSentinelPackageInfo struct {
	ImportPath, Dir, Export, ForTest                                                                            string
	Incomplete                                                                                                  bool
	GoFiles, CompiledGoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SysoFiles, EmbedFiles []string
	ImportMap                                                                                                   map[string]string
	Module                                                                                                      *struct{ GoVersion string }
	Error                                                                                                       *struct{ Err string }
	DepsErrors                                                                                                  []struct{ Err string }
}

// proveWorkerSentinel compiles export data but never runs a consumer, package
// init, or test. Its caller must retain the existing whole-snapshot before/after
// comparison. All sources are also checked against s before and after this scan.
func proveWorkerSentinel(s workerSnapshot) (workerSentinelEvidence, error) {
	var result workerSentinelEvidence
	if runtime.Version() != s.Consumer.Profile["GOVERSION"] || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return result, errors.New("sentinel checker toolchain/profile mismatch")
	}
	if err := checkEnvironment(os.Getenv); err != nil {
		return result, err
	}
	if err := checkCommandTarget(s.Consumer.Command.Target); err != nil {
		return result, err
	}
	data, err := commandOutput(s.Consumer.GoExecutable, s.Consumer.Root, selectedEnvironment(s.Consumer.GoExecutable), "list", "-deps", "-compiled", "-export", "-json", s.Consumer.Command.Target)
	if err != nil {
		return result, err
	}
	var packages []workerSentinelPackageInfo
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var p workerSentinelPackageInfo
		err = decoder.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.New("invalid sentinel selected closure")
		}
		if p.ImportPath == "" || p.Dir == "" || p.Incomplete || p.Error != nil || len(p.DepsErrors) > 0 || p.ForTest != "" || len(p.CgoFiles) > 0 {
			return result, errors.New("incomplete or unsupported sentinel selected closure")
		}
		packages = append(packages, p)
	}
	return checkWorkerSentinelClosure(s, packages)
}

func checkWorkerSentinelClosure(s workerSnapshot, packages []workerSentinelPackageInfo) (workerSentinelEvidence, error) {
	result := workerSentinelEvidence{Scope: "typed-go-sentinel-writes-and-addresses-only-v1", ExportSHA256: map[string]string{}, OpaqueInputs: map[string]string{}}
	inputs := map[string]string{}
	paths := map[string]string{}
	exports := map[string]string{}
	names := make([]string, 0, len(packages))
	for _, p := range packages {
		if _, duplicate := exports[p.ImportPath]; duplicate {
			return result, errors.New("duplicate sentinel package")
		}
		exports[p.ImportPath] = p.Export
		names = append(names, p.ImportPath)
		if p.Export == "" && p.ImportPath != "unsafe" {
			return result, errors.New("missing selected export data")
		}
		for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SysoFiles, p.EmbedFiles} {
			for _, name := range list {
				key := "closure/" + p.ImportPath + "/" + filepath.ToSlash(name)
				hash, err := workerRegularHash(p.Dir, filepath.ToSlash(name))
				if err != nil || s.Inputs[key] != hash {
					return result, errors.New("sentinel source differs from snapshot")
				}
				inputs[key] = hash
				paths[key] = filepath.Join(p.Dir, name)
			}
		}
		// Under CGO0 the compiled Go inputs must be exactly the captured Go inputs.
		// Unknown generated/transformed sources are refused, not silently omitted.
		compiled := make([]string, 0, len(p.CompiledGoFiles))
		for _, name := range p.CompiledGoFiles {
			if filepath.IsAbs(name) {
				relative, err := filepath.Rel(p.Dir, name)
				if err != nil {
					return result, err
				}
				name = relative
			}
			compiled = append(compiled, filepath.ToSlash(name))
		}
		wanted := slices.Clone(p.GoFiles)
		sort.Strings(wanted)
		sort.Strings(compiled)
		// unsafe is compiler-provided: its captured Go file documents builtins
		// and go list intentionally has no compiled source or export archive.
		if (p.ImportPath != "unsafe" || len(compiled) != 0) && !slices.Equal(wanted, compiled) {
			return result, errors.New("sentinel compiled source set differs from capture")
		}
		for _, list := range [][]string{p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SysoFiles} {
			for _, name := range list {
				key := "closure/" + p.ImportPath + "/" + filepath.ToSlash(name)
				result.OpaqueInputs[key] = inputs[key]
			}
		}
	}
	sort.Strings(names)
	if !slices.Equal(names, s.Packages) || !slices.Contains(names, workerSentinelPackage) {
		return result, errors.New("sentinel import closure differs from snapshot")
	}
	for key := range s.Inputs {
		if strings.HasPrefix(key, "closure/") {
			if _, ok := inputs[key]; !ok {
				return result, errors.New("sentinel source closure incomplete")
			}
		}
	}
	fs := token.NewFileSet()
	imp := importer.ForCompiler(fs, "gc", func(path string) (io.ReadCloser, error) {
		name, ok := exports[path]
		if !ok || name == "" {
			return nil, errors.New("unselected sentinel export import")
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		result.ExportSHA256[path] = hashBytes(raw)
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	for _, p := range packages {
		files := make([]*ast.File, 0, len(p.GoFiles))
		needsTypes := p.ImportPath == workerSentinelPackage
		for _, name := range p.GoFiles {
			raw, err := os.ReadFile(filepath.Join(p.Dir, name))
			if err != nil {
				return result, err
			}
			if hashBytes(raw) != inputs["closure/"+p.ImportPath+"/"+filepath.ToSlash(name)] {
				return result, errors.New("sentinel input changed during parse")
			}
			f, err := parser.ParseFile(fs, filepath.Join(p.Dir, name), raw, parser.ParseComments)
			if err != nil {
				return result, errors.New("sentinel source parse failed")
			}
			if err = checkWorkerSentinelLinknames(f, p.ImportPath); err != nil {
				return result, err
			}
			for _, spec := range f.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return result, err
				}
				needsTypes = needsTypes || path == workerSentinelPackage
			}
			files = append(files, f)
		}
		if !needsTypes {
			continue
		}
		version := s.Consumer.Profile["GOVERSION"]
		if p.Module != nil && p.Module.GoVersion != "" {
			version = "go" + p.Module.GoVersion
		}
		if err := checkWorkerSentinelAST(fs, files, p.ImportPath, version, workerSentinelImporter{imp, p.ImportMap}); err != nil {
			return result, err
		}
		result.CheckedPackages = append(result.CheckedPackages, p.ImportPath)
	}
	for key, path := range paths {
		hash, err := fileHash(path)
		if err != nil || hash != inputs[key] {
			return result, errors.New("sentinel input changed during analysis")
		}
	}
	sort.Strings(result.CheckedPackages)
	result.InputsSHA256 = workerJSONHash(inputs)
	return result, nil
}

type workerSentinelImporter struct {
	base    types.Importer
	aliases map[string]string
}

func (i workerSentinelImporter) Import(path string) (*types.Package, error) {
	if selected, ok := i.aliases[path]; ok {
		path = selected
	}
	return i.base.Import(path)
}

func checkWorkerSentinelLinknames(f *ast.File, path string) error {
	for _, group := range f.Comments {
		for _, comment := range group.List {
			words := strings.Fields(comment.Text)
			if len(words) > 1 && words[0] == "//go:linkname" && ((path == workerSentinelPackage && words[1] == workerSentinelName) || (len(words) > 2 && words[2] == workerSentinelPackage+"."+workerSentinelName)) {
				return errors.New("sentinel linkname requires separate review")
			}
		}
	}
	return nil
}

func checkWorkerSentinelAST(fs *token.FileSet, files []*ast.File, path, version string, imp types.Importer) error {
	for _, f := range files {
		if err := checkWorkerSentinelLinknames(f, path); err != nil {
			return err
		}
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	config := types.Config{Importer: imp, GoVersion: version, Sizes: types.SizesFor("gc", "amd64")}
	pkg, err := config.Check(path, fs, files, info)
	if err != nil {
		return errors.New("sentinel source type check failed")
	}
	if path == workerSentinelPackage {
		v, ok := pkg.Scope().Lookup(workerSentinelName).(*types.Var)
		if !ok || !types.Identical(v.Type(), types.Universe.Lookup("error").Type()) {
			return errors.New("sentinel declaration does not match reviewed shape")
		}
	}
	isSentinel := func(expr ast.Expr) bool {
		var id *ast.Ident
		switch v := ast.Unparen(expr).(type) {
		case *ast.Ident:
			id = v
		case *ast.SelectorExpr:
			id = v.Sel
		default:
			return false
		}
		obj := info.ObjectOf(id)
		v, ok := obj.(*types.Var)
		return ok && v.Pkg() != nil && v.Pkg().Path() == workerSentinelPackage && v.Name() == workerSentinelName && v == v.Pkg().Scope().Lookup(workerSentinelName)
	}
	var problem error
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if problem != nil {
				return false
			}
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if isSentinel(lhs) {
						problem = errors.New("sentinel assignment is outside the reviewed domain")
					}
				}
			case *ast.RangeStmt:
				if (v.Key != nil && isSentinel(v.Key)) || (v.Value != nil && isSentinel(v.Value)) {
					problem = errors.New("sentinel assignment is outside the reviewed domain")
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND && isSentinel(v.X) {
					problem = errors.New("sentinel address escapes the reviewed domain")
				}
			}
			return problem == nil
		})
	}
	return problem
}
