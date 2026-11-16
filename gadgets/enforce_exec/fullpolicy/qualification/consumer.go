// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
)

const (
	gadgetModule    = "github.com/inspektor-gadget/inspektor-gadget"
	evidenceVersion = 1
)

type selectedModule struct {
	Path, Version, Sum, Dir, GoMod string
	Main                           bool
	Replace                        *selectedModule `json:",omitempty"`
}
type selectedPackage struct {
	ImportPath, Dir string
	Module          *selectedModule
}
type consumerSnapshot struct {
	ResolverHashes map[string]string `json:"resolver_configuration_sha256"`
	Modules        []debug.Module    `json:"selected_mvs_dependencies"`
	Command        consumerCommand   `json:"command"`
	Root           string            `json:"root"`
	GoExecutable   string            `json:"go_executable"`
	ToolHashes     map[string]string `json:"tool_hashes"`
	Profile        map[string]string `json:"test_profile"`
	AuditedSources map[string]string `json:"audited_sources"`
	Package        selectedPackage   `json:"selected_package"`
	Inputs         map[string]string `json:"inputs"`
	GraphHash      string            `json:"module_graph_sha256"`
}
type runnerIdentity struct {
	Executable, SHA256 string
	BuildInfo          *debug.BuildInfo
	SourceLinkage      string `json:"source_linkage"`
}
type binaryEvidence struct {
	Path      string           `json:"path"`
	SHA256    string           `json:"sha256"`
	BuildInfo *debug.BuildInfo `json:"actual_build_info"`
}
type consumerReport struct {
	Phase                 string           `json:"phase"`
	BindRunner            *runnerIdentity  `json:"binding_runner,omitempty"`
	SchemaVersion         int              `json:"schema_version"`
	EvidenceScope         string           `json:"evidence_scope"`
	NativeBudgetQualified *bool            `json:"native_budget_qualified"`
	CompleteModelRevision json.RawMessage  `json:"complete_model_revision"`
	ArtifactLinkage       string           `json:"artifact_linkage"`
	AuditedSourceRevision string           `json:"audited_source_revision"`
	Snapshot              consumerSnapshot `json:"snapshot"`
	PassedTests           []string         `json:"passed_tests"`
	Runner                runnerIdentity   `json:"runner"`
	Binary                *binaryEvidence  `json:"binary,omitempty"`
	PrebuildReportHash    string           `json:"prebuild_report_sha256,omitempty"`
}

func checkSelectedModule(m selectedModule) error {
	if m.Path != gadgetModule || m.Main || !strings.HasPrefix(m.Version, "v") {
		return errors.New("fullpolicy must be a versioned dependency, not a main/local module")
	}
	effective := &m
	if m.Replace != nil {
		effective = m.Replace
	}
	if effective.Main || effective.Version == "" || !strings.HasPrefix(effective.Version, "v") || !strings.Contains(effective.Path, ".") || filepath.IsAbs(effective.Path) || strings.HasPrefix(effective.Path, ".") || !strings.HasPrefix(effective.Sum, "h1:") || effective.Replace != nil {
		return errors.New("effective fullpolicy module must have a remote version and checksum")
	}
	return nil
}

func commandOutput(executable, dir string, env []string, args ...string) ([]byte, error) {
	c := exec.Command(executable, args...)
	c.Dir = dir
	c.Env = env
	data, err := c.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, goCommandError(args[0], err, exit.Stderr)
		}
		return nil, goCommandError(args[0], err, nil)
	}
	return data, nil
}

func selectedEnvironment(executable string) []string {
	return append(os.Environ(), "PATH="+filepath.Dir(executable)+string(os.PathListSeparator)+os.Getenv("PATH"))
}
func hashBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func snapshotConsumer(goPath, root, target string) (consumerSnapshot, error) {
	var s consumerSnapshot
	if err := checkEnvironment(os.Getenv); err != nil {
		return s, err
	}
	if !filepath.IsAbs(goPath) {
		return s, errors.New("-go requires an absolute executable path")
	}
	var err error
	s.GoExecutable, err = filepath.EvalSymlinks(goPath)
	if err != nil {
		return s, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return s, err
	}
	s.Root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return s, err
	}
	initialInputs := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		h, e := fileHash(filepath.Join(s.Root, name))
		if e != nil {
			return s, e
		}
		initialInputs[name] = h
	}
	env := selectedEnvironment(s.GoExecutable)
	s.Command, err = snapshotCommand(s.GoExecutable, s.Root, target, env)
	if err != nil {
		return s, err
	}
	args := []string{"env", "-json", "GOVERSION", "GOROOT", "GOMOD", "GOFIPS140", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOPROXY", "GOPRIVATE", "GOMODCACHE"}
	for key := range requiredEnvironment {
		args = append(args, key)
	}
	data, err := commandOutput(s.GoExecutable, s.Root, env, args...)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(data, &s.Profile); err != nil {
		return s, err
	}
	s.ResolverHashes = publishResolverHashes(s.Profile)
	if err = checkToolchain(s.Profile); err != nil {
		return s, err
	}
	if s.Profile["GOFIPS140"] != "off" {
		return s, errors.New("unsupported GOFIPS140")
	}
	if s.Profile["GOMOD"] != filepath.Join(s.Root, "go.mod") {
		return s, errors.New("consumer must be its module root")
	}
	actual, err := filepath.EvalSymlinks(filepath.Join(s.Profile["GOROOT"], "bin", "go"))
	if err != nil || actual != s.GoExecutable {
		return s, errors.New("selected executable does not match effective GOROOT")
	}
	if err = json.Unmarshal(sourceManifest, &s.AuditedSources); err != nil {
		return s, err
	}
	if len(s.AuditedSources) != 15 {
		return s, errors.New("incomplete source manifest")
	}
	if err = checkSources(s.Profile["GOROOT"], s.AuditedSources); err != nil {
		return s, err
	}
	s.ToolHashes = map[string]string{}
	for _, name := range []string{"bin/go", "pkg/tool/linux_amd64/compile", "pkg/tool/linux_amd64/asm", "pkg/tool/linux_amd64/link"} {
		h, e := fileHash(filepath.Join(s.Profile["GOROOT"], name))
		if e != nil {
			return s, e
		}
		s.ToolHashes[name] = h
	}
	data, err = commandOutput(s.GoExecutable, s.Root, env, "list", "-json", testedPackage)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(data, &s.Package); err != nil {
		return s, err
	}
	if s.Package.ImportPath != testedPackage || s.Package.Module == nil {
		return s, errors.New("unexpected fullpolicy package selection")
	}
	if err = checkSelectedModule(*s.Package.Module); err != nil {
		return s, err
	}
	effective := s.Package.Module
	if effective.Replace != nil {
		effective = effective.Replace
	}
	if s.Package.Dir != filepath.Join(effective.Dir, "gadgets/enforce_exec/fullpolicy") {
		return s, errors.New("selected package/source directory mismatch")
	}
	if _, err := os.Lstat(filepath.Join(s.Package.Dir, "default.pgo")); !errors.Is(err, os.ErrNotExist) {
		return s, errors.New("implicit model-test default.pgo is unsupported")
	}
	s.Inputs = map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		h, e := fileHash(filepath.Join(s.Root, name))
		if e != nil {
			return s, e
		}
		if h != initialInputs[name] {
			return s, errors.New("consumer manifests changed during graph resolution")
		}
		s.Inputs["consumer/"+name] = h
	}
	h, err := fileHash(effective.GoMod)
	if err != nil {
		return s, err
	}
	s.Inputs["selected-module/go.mod"] = h
	// Full selected package tree includes model tests, command sources, embeds
	// and testdata, not just the current command's own checkout.
	err = filepath.WalkDir(s.Package.Dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in selected source tree: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular selected input: %s", path)
		}
		relative, e := filepath.Rel(s.Package.Dir, path)
		if e != nil {
			return e
		}
		h, e := fileHash(path)
		if e != nil {
			return e
		}
		s.Inputs["fullpolicy/"+filepath.ToSlash(relative)] = h
		return nil
	})
	if err != nil {
		return s, err
	}
	for _, name := range []string{"workspace_syntax.go", "workspace_syntax_test.go", "qualification/main.go", "qualification/sources.json"} {
		if s.Inputs["fullpolicy/"+name] == "" {
			return s, fmt.Errorf("selected dependency lacks required model/command input %s", name)
		}
	}
	data, err = commandOutput(s.GoExecutable, s.Root, env, "mod", "graph")
	if err != nil {
		return s, err
	}
	s.GraphHash = hashBytes(data)
	s.Modules, err = selectedModules(s.GoExecutable, s.Root, s.Command.MainModule, env)
	if err != nil {
		return s, err
	}
	if err = checkLinkedModules([]*debug.Module{ptrModule(moduleIdentity(*s.Package.Module))}, s.Modules); err != nil {
		return s, errors.New("selected package differs from MVS inventory")
	}
	return s, nil
}

func newConsumerReport(s consumerSnapshot) (consumerReport, error) {
	no := false
	r := consumerReport{Phase: "PREBUILD", SchemaVersion: evidenceVersion, EvidenceScope: "syntax-model", NativeBudgetQualified: &no, CompleteModelRevision: json.RawMessage("null"), ArtifactLinkage: "ABSENT", AuditedSourceRevision: sourceRevision, Snapshot: s, PassedTests: append([]string(nil), requiredTests...)}
	exe, err := os.Executable()
	if err != nil {
		return r, err
	}
	r.Runner.Executable, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return r, err
	}
	runnerBytes, err := os.ReadFile(r.Runner.Executable)
	if err != nil {
		return r, err
	}
	r.Runner.SHA256 = hashBytes(runnerBytes)
	r.Runner.BuildInfo, err = buildinfo.Read(bytes.NewReader(runnerBytes))
	if err != nil {
		return r, err
	}
	r.Runner.SourceLinkage = "UNPROVEN"
	return r, nil
}

func validatePrebuild(r consumerReport) error {
	if r.Phase != "PREBUILD" || r.SchemaVersion != evidenceVersion || r.EvidenceScope != "syntax-model" || r.NativeBudgetQualified == nil || *r.NativeBudgetQualified || string(r.CompleteModelRevision) != "null" || r.ArtifactLinkage != "ABSENT" || r.AuditedSourceRevision != sourceRevision || r.Binary != nil || r.BindRunner != nil || r.PrebuildReportHash != "" || r.Runner.SourceLinkage != "UNPROVEN" || r.Runner.SHA256 == "" || r.Runner.BuildInfo == nil || !reflect.DeepEqual(r.PassedTests, requiredTests) {
		return errors.New("incomplete or incompatible syntax-model prebuild evidence")
	}
	if !filepath.IsAbs(r.Snapshot.Root) || !filepath.IsAbs(r.Snapshot.GoExecutable) || r.Snapshot.Package.Module == nil {
		return errors.New("missing source/tool identity")
	}
	if err := checkSelectedModule(*r.Snapshot.Package.Module); err != nil {
		return err
	}
	if r.Snapshot.Package.ImportPath != testedPackage || r.Snapshot.Package.Dir == "" {
		return errors.New("missing selected package")
	}
	for _, key := range resolverKeys {
		if _, exists := r.Snapshot.Profile[key]; exists {
			return errors.New("raw resolver settings are not allowed in reports")
		}
		if !validHash(r.Snapshot.ResolverHashes[key]) {
			return errors.New("missing resolver configuration digest")
		}
	}
	if len(r.Snapshot.Modules) == 0 {
		return errors.New("missing selected MVS inventory")
	}
	if err := checkLinkedModules([]*debug.Module{ptrModule(moduleIdentity(*r.Snapshot.Package.Module))}, r.Snapshot.Modules); err != nil {
		return err
	}
	if err := checkToolchain(r.Snapshot.Profile); err != nil {
		return err
	}
	var manifest map[string]string
	if err := json.Unmarshal(sourceManifest, &manifest); err != nil {
		return err
	}
	if !reflect.DeepEqual(r.Snapshot.AuditedSources, manifest) {
		return errors.New("incomplete audited source pins")
	}
	for _, key := range []string{"bin/go", "pkg/tool/linux_amd64/compile", "pkg/tool/linux_amd64/asm", "pkg/tool/linux_amd64/link"} {
		if !validHash(r.Snapshot.ToolHashes[key]) {
			return errors.New("missing tool hash")
		}
	}
	for _, key := range []string{"consumer/go.mod", "consumer/go.sum", "selected-module/go.mod", "fullpolicy/workspace_syntax.go", "fullpolicy/workspace_syntax_test.go", "fullpolicy/qualification/main.go", "fullpolicy/qualification/sources.json"} {
		if !validHash(r.Snapshot.Inputs[key]) {
			return errors.New("missing model/consumer input hash")
		}
	}
	if !validHash(r.Snapshot.GraphHash) || !validHash(r.Runner.SHA256) || r.Runner.BuildInfo.GoVersion == "" || r.Runner.Executable == "" {
		return errors.New("missing graph/runner identity")
	}
	c := r.Snapshot.Command
	if err := checkCommandTarget(c.Target); err != nil {
		return err
	}
	if c.MainModule == "" || c.ImportPath == "" || len(c.Files) == 0 || c.IdentityLimitation == "" || !c.ImplicitPGOAbsent {
		return errors.New("missing command identity")
	}
	for _, h := range c.Files {
		if !validHash(h) {
			return errors.New("invalid command input hash")
		}
	}
	return nil
}

func readPrebuild(path string) (consumerReport, string, error) {
	var r consumerReport
	data, err := os.ReadFile(path)
	if err != nil {
		return r, "", err
	}
	if err = checkUniqueJSON(data); err != nil {
		return r, "", err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, "", err
	}
	if err = d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return r, "", errors.New("trailing report content")
	}
	// encoding/json otherwise accepts case-insensitive aliases of struct
	// fields. Require the exact generated schema, not last-alias-wins input.
	canonical, err := json.Marshal(r)
	if err != nil {
		return r, "", err
	}
	var rawShape, canonicalShape any
	if err = json.Unmarshal(data, &rawShape); err != nil {
		return r, "", err
	}
	if err = json.Unmarshal(canonical, &canonicalShape); err != nil {
		return r, "", err
	}
	if !reflect.DeepEqual(rawShape, canonicalShape) {
		return r, "", errors.New("report does not use the exact versioned schema")
	}
	if err = validatePrebuild(r); err != nil {
		return r, "", err
	}
	return r, hashBytes(data), nil
}

func runConsumer(goPath, root, target, checkReport, binaryPath, reportPath string, events, logs io.Writer) error {
	if reportPath == "" {
		return errors.New("consumer mode requires -report")
	}
	if (checkReport == "") != (binaryPath == "") {
		return errors.New("binding requires both -check-report and -bind-binary")
	}
	// Never overwrite an input or a previous successful record with new evidence.
	if _, err := os.Lstat(reportPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("report output must not already exist")
	}
	before, err := snapshotConsumer(goPath, root, target)
	if err != nil {
		return err
	}
	var r consumerReport
	var binaryIdentity os.FileInfo
	if checkReport == "" {
		c := exec.Command(before.GoExecutable, "test", "-json", "-count=1", "-run", "^("+strings.Join(requiredTests, "|")+")$", testedPackage)
		c.Dir = before.Root
		c.Env = selectedEnvironment(before.GoExecutable)
		if err = runModelTests(c, events, logs); err != nil {
			return err
		}
		r, err = newConsumerReport(before)
		if err != nil {
			return err
		}
	} else {
		var preHash string
		r, preHash, err = readPrebuild(checkReport)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, r.Snapshot) {
			return errors.New("consumer/tool/source/module inputs differ from prebuild evidence")
		}
		binaryPath, err = filepath.Abs(binaryPath)
		if err != nil {
			return err
		}
		binaryBefore, err := os.Stat(binaryPath)
		if err != nil {
			return err
		}
		binaryIdentity = binaryBefore
		if !binaryBefore.Mode().IsRegular() {
			return errors.New("binary must be regular")
		}
		binaryData, err := os.ReadFile(binaryPath)
		if err != nil {
			return err
		}
		h := hashBytes(binaryData)
		info, err := buildinfo.Read(bytes.NewReader(binaryData))
		if err != nil {
			return err
		}
		if err = checkBinaryCommand(info, before.Command); err != nil {
			return err
		}
		if err = checkBinaryInfo(before.Modules, info, *before.Package.Module, before.Profile); err != nil {
			return err
		}
		bindingRunner, e := newConsumerReport(before)
		if e != nil {
			return e
		}
		r.BindRunner = &bindingRunner.Runner
		binaryAfter, e := os.Stat(binaryPath)
		if e != nil {
			return e
		}
		afterHash, e := fileHash(binaryPath)
		if e != nil {
			return e
		}
		if !os.SameFile(binaryBefore, binaryAfter) || binaryBefore.Size() != binaryAfter.Size() || !binaryBefore.ModTime().Equal(binaryAfter.ModTime()) || afterHash != h {
			return errors.New("binary changed during binding")
		}
		r.Binary = &binaryEvidence{Path: binaryPath, SHA256: h, BuildInfo: info}
		r.ArtifactLinkage = "LINKED_BINARY_ONLY"
		r.Phase = "BUILD"
		r.PrebuildReportHash = preHash
	}
	after, err := snapshotConsumer(goPath, root, target)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("consumer/tool/source/module inputs changed during evidence collection")
	}
	if r.Binary != nil {
		current, e := os.Stat(r.Binary.Path)
		if e != nil {
			return e
		}
		h, e := fileHash(r.Binary.Path)
		if e != nil {
			return e
		}
		if !os.SameFile(binaryIdentity, current) || binaryIdentity.Size() != current.Size() || !binaryIdentity.ModTime().Equal(current.ModTime()) || h != r.Binary.SHA256 {
			return errors.New("binary changed before report publication")
		}
		prior, e := fileHash(checkReport)
		if e != nil {
			return e
		}
		if prior != r.PrebuildReportHash {
			return errors.New("prebuild report changed during binding")
		}
	}
	return writeReport(reportPath, r)
}

func writeReport(path string, record any) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}
