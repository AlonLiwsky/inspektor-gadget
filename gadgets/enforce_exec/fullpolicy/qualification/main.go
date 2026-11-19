// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command qualification corroborates the local syntax workspace model only.
// It does not attest a consuming artifact or authorize runtime memory admission.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	testedPackage  = "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	sourceRevision = "2aae1000ea1d4b28923b96db28acf4e3b99d6aff"
)

// Pins originate from the immutable official Go commit, not from the local
// GOROOT under examination: eleven model inputs plus four controlling source
// files for the exact empty/greenteagc raw-profile alias.
//
//go:embed sources.json
var sourceManifest []byte

var requiredEnvironment = map[string]string{
	"GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly",
	"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0",
	"GOEXPERIMENT": "", "GODEBUG": "", "GOCOMPILEDEBUG": "",
}

var requiredTests = []string{
	"TestSyntaxWorkspaceQualification", "TestSyntaxWorkspaceRuntimeCapacities",
	"TestSyntaxWorkspaceHistories", "TestSyntaxWorkspaceKnownCosts", "TestSyntaxWorkspaceOverflow",
	"TestSyntaxWorkspaceNonallocating", "TestSyntaxWorkspaceHeaderRounding", "TestSyntaxWorkspaceInstructionOverlap",
	"TestSyntaxWorkspaceGrowthSupremum", "TestSyntaxWorkspaceParserComposition", "TestSyntaxWorkspaceConcatHistories",
	"TestSyntaxWorkspaceCheckedComposition", "TestSyntaxWorkspaceResetAndRejectPrefixes",
	"TestSyntaxWorkspaceGeneratedGrammar", "TestSyntaxWorkspaceParserSourceIdentity",
}

func checkEnvironment(get func(string) string) error {
	for key, want := range requiredEnvironment {
		got := get(key)
		if key == "GOEXPERIMENT" {
			// Pinned Go already enables GreenTeaGC by default. Preserve the raw
			// value in go env/reporting; do not canonicalize arbitrary settings.
			if got != "" && got != "greenteagc" {
				return fmt.Errorf("unsupported GOEXPERIMENT=%q; require empty or greenteagc", got)
			}
			continue
		}
		if got != want {
			return fmt.Errorf("unsupported %s=%q; require %q", key, got, want)
		}
	}
	return nil
}

func checkToolchain(values map[string]string) error {
	if values["GOVERSION"] != "go1.27.3" {
		return fmt.Errorf("unsupported GOVERSION=%q", values["GOVERSION"])
	}
	// go env reports the disabled GOENV file as an empty path, although the
	// explicitly supplied environment must say GOENV=off.
	if values["GOENV"] != "" {
		return errors.New("effective GOENV file is not disabled")
	}
	return checkEnvironment(func(k string) string {
		if k == "GOENV" {
			return "off"
		}
		return values[k]
	})
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func checkSources(root string, manifest map[string]string) error {
	for name, want := range manifest {
		got, err := fileHash(filepath.Join(root, "src", filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("source %s: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("audited source %s changed: %s", name, got)
		}
	}
	return nil
}

type testEvent struct{ Action, Package, Test string }

func checkTestEvents(reader io.Reader, processErr error) error {
	if processErr != nil {
		return fmt.Errorf("qualification test process failed: %w", processErr)
	}
	state := map[string]int{}
	for _, name := range requiredTests {
		state[name] = 0
	}
	decoder := json.NewDecoder(reader)
	started, passed := false, false
	for {
		var event testEvent
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("invalid test JSON: %w", err)
		}
		if event.Package != testedPackage || passed {
			return fmt.Errorf("unexpected test package/event: %+v", event)
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("qualification test did not pass: %+v", event)
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				if started {
					return errors.New("duplicate package start")
				}
				started = true
			case "output":
				if !started {
					return errors.New("output before package start")
				}
			case "pass":
				if !started {
					return errors.New("package pass before start")
				}
				passed = true
			default:
				return fmt.Errorf("unexpected package action %q", event.Action)
			}
			continue
		}
		if !started {
			return errors.New("test before package start")
		}
		if strings.Contains(event.Test, "/") {
			return fmt.Errorf("unexpected selected subtest %q", event.Test)
		}
		value, ok := state[event.Test]
		if !ok {
			return fmt.Errorf("unexpected test %q", event.Test)
		}
		switch event.Action {
		case "run":
			if value != 0 {
				return fmt.Errorf("duplicate test run %s", event.Test)
			}
			state[event.Test] = 1
		case "pass":
			if value != 1 {
				return fmt.Errorf("test pass without run %s", event.Test)
			}
			state[event.Test] = 2
		case "output":
			if value != 1 {
				return fmt.Errorf("test output outside run %s", event.Test)
			}
		default:
			return fmt.Errorf("unexpected test action %q", event.Action)
		}
	}
	if !passed {
		return errors.New("missing package pass")
	}
	for name, value := range state {
		if value != 2 {
			return fmt.Errorf("missing run/pass for %s", name)
		}
	}
	return nil
}

func inputHashes(repo string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(repo, "gadgets/enforce_exec/fullpolicy", "*.go"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("missing fullpolicy inputs")
	}
	paths = append(paths, filepath.Join(repo, "go.mod"), filepath.Join(repo, "go.sum"))
	result := map[string]string{}
	for _, path := range paths {
		hash, err := fileHash(path)
		if err != nil {
			return nil, err
		}
		relative, err := filepath.Rel(repo, path)
		if err != nil {
			return nil, err
		}
		result[relative] = hash
	}
	return result, nil
}

func run(goPath, repo string, output, report io.Writer) error {
	if err := checkEnvironment(os.Getenv); err != nil {
		return err
	}
	if !filepath.IsAbs(goPath) {
		return errors.New("-go requires an absolute executable path")
	}
	executable, err := filepath.EvalSymlinks(goPath)
	if err != nil {
		return err
	}
	repo, err = filepath.Abs(repo)
	if err != nil {
		return err
	}
	// The identity test itself invokes `go`: bind its PATH lookup to the same
	// selected executable directory rather than an unrelated ambient toolchain.
	env := append(os.Environ(), "PATH="+filepath.Dir(executable)+string(os.PathListSeparator)+os.Getenv("PATH"))
	args := []string{"env", "-json", "GOVERSION", "GOROOT"}
	for key := range requiredEnvironment {
		args = append(args, key)
	}
	command := exec.Command(executable, args...)
	command.Dir = repo
	command.Env = env
	data, err := command.Output()
	if err != nil {
		return fmt.Errorf("go env: %w", err)
	}
	profile := map[string]string{}
	if err = json.Unmarshal(data, &profile); err != nil {
		return err
	}
	if err = checkToolchain(profile); err != nil {
		return err
	}
	rootExecutable, err := filepath.EvalSymlinks(filepath.Join(profile["GOROOT"], "bin", "go"))
	if err != nil || rootExecutable != executable {
		return errors.New("selected executable does not match effective GOROOT")
	}
	manifest := map[string]string{}
	if err = json.Unmarshal(sourceManifest, &manifest); err != nil {
		return err
	}
	if len(manifest) != 15 {
		return errors.New("incomplete audited source manifest")
	}
	if err = checkSources(profile["GOROOT"], manifest); err != nil {
		return err
	}
	executableHash, err := fileHash(executable)
	if err != nil {
		return err
	}
	inputs, err := inputHashes(repo)
	if err != nil {
		return err
	}
	command = exec.Command(executable, "test", "-json", "-count=1", "-run", "^("+strings.Join(requiredTests, "|")+")$", "./gadgets/enforce_exec/fullpolicy")
	command.Dir = repo
	command.Env = env
	if err = runModelTests(command, output, os.Stderr); err != nil {
		return err
	}
	if err = checkSources(profile["GOROOT"], manifest); err != nil {
		return err
	}
	after, err := inputHashes(repo)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(inputs, after) {
		return errors.New("model inputs changed during corroboration")
	}
	afterExecutable, err := fileHash(executable)
	if err != nil {
		return err
	}
	if afterExecutable != executableHash {
		return errors.New("go executable changed during corroboration")
	}
	return json.NewEncoder(report).Encode(map[string]any{"schema_version": evidenceVersion, "evidence_scope": "syntax-model", "native_budget_qualified": false, "complete_model_revision": nil, "result": "local model/source corroboration only", "artifact_linkage": "ABSENT: not production attestation or complete CompileBytes admission", "go_executable": executable, "go_executable_sha256": executableHash, "effective_profile": profile, "audited_source_revision": sourceRevision, "audited_sources": manifest, "worktree_inputs": inputs, "passed_tests": requiredTests})
}

func main() {
	goPath := flag.String("go", "", "absolute path to audited go executable")
	repo := flag.String("repo", ".", "repository root")
	consumerCommand := flag.String("consumer-command", "", "one module-relative main package (file targets unsupported)")
	consumer := flag.String("consumer", "", "consumer module root (versioned dependency evidence)")
	checkReport := flag.String("check-report", "", "prebuild JSON report to recheck")
	binary := flag.String("bind-binary", "", "final executable to bind")
	reportPath := flag.String("report", "", "new dedicated JSON output file")
	worker := flag.Bool("worker", false, "distinct fresh-scope logical worker producer (not native qualification)")
	workerPrebuild := flag.String("worker-prebuild", "", "exact worker PREBUILD for controlled BUILD")
	workerOutput := flag.String("worker-output", "", "new controlled worker executable output")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no additional Go flags accepted")
		os.Exit(1)
	}
	var err error
	if *worker {
		if *repo != "." || *checkReport != "" || *binary != "" {
			err = errors.New("worker mode cannot use syntax/repo/posthoc binary flags")
		} else {
			err = runWorker(*goPath, *consumer, *consumerCommand, *workerPrebuild, *workerOutput, *reportPath)
		}
	} else if *workerPrebuild != "" || *workerOutput != "" {
		err = errors.New("worker flags require -worker")
	} else if *consumer != "" {
		if *repo != "." {
			err = errors.New("-repo cannot be combined with -consumer")
		} else {
			err = runConsumer(*goPath, *consumer, *consumerCommand, *checkReport, *binary, *reportPath, os.Stdout, os.Stderr)
		}
	} else if *checkReport != "" || *binary != "" || *consumerCommand != "" {
		err = errors.New("binding flags require -consumer")
	} else if *reportPath != "" {
		var record bytes.Buffer
		err = run(*goPath, *repo, os.Stdout, &record)
		if err == nil {
			var value json.RawMessage = record.Bytes()
			err = writeReport(*reportPath, value)
		}
	} else {
		err = run(*goPath, *repo, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
