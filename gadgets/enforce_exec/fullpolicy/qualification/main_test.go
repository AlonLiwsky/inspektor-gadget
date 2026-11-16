// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRefusals(t *testing.T) {
	good := map[string]string{}
	for k, v := range requiredEnvironment {
		good[k] = v
	}
	if err := checkEnvironment(func(k string) string { return good[k] }); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GOFLAGS", "GOTOOLCHAIN", "GOENV", "GOWORK", "GOEXPERIMENT", "GOARCH", "GOOS", "CGO_ENABLED", "GODEBUG"} {
		t.Run(key, func(t *testing.T) {
			bad := map[string]string{}
			for k, v := range good {
				bad[k] = v
			}
			bad[key] = "unsupported"
			if err := checkEnvironment(func(k string) string { return bad[k] }); err == nil {
				t.Fatal("accepted unsupported setting")
			}
		})
	}
	if err := checkToolchain(map[string]string{"GOVERSION": "go1.27.4"}); err == nil {
		t.Fatal("wrong version accepted")
	}
}

func TestSourceRefusals(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "src", "sample.go")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("audited source")
	manifest := map[string]string{"sample.go": fmt.Sprintf("%x", sha256.Sum256(data))}
	if err := checkSources(root, manifest); err == nil {
		t.Fatal("missing source accepted")
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkSources(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkSources(root, manifest); err == nil {
		t.Fatal("changed source accepted")
	}
}

func goodEvents() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{\"Action\":\"start\",\"Package\":%q}\n", testedPackage)
	for _, name := range requiredTests {
		for _, action := range []string{"run", "pass"} {
			fmt.Fprintf(&b, "{\"Action\":%q,\"Package\":%q,\"Test\":%q}\n", action, testedPackage, name)
		}
	}
	fmt.Fprintf(&b, "{\"Action\":\"pass\",\"Package\":%q}\n", testedPackage)
	return b.String()
}

func TestTestEventRefusals(t *testing.T) {
	good := goodEvents()
	if err := checkTestEvents(strings.NewReader(good), nil); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"empty": "", "malformed": good + "not json", "missing": strings.ReplaceAll(good, requiredTests[0], "OtherTest"),
		"skip":             strings.Replace(good, `"Action":"pass"`, `"Action":"skip"`, 1),
		"pass without run": strings.Replace(good, `"Action":"run"`, `"Action":"output"`, 1),
		"no package pass":  good[:strings.LastIndex(strings.TrimSuffix(good, "\n"), "\n")],
		"null":             "null\n", "duplicate": good + good,
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkTestEvents(bytes.NewBufferString(data), nil); err == nil {
				t.Fatal("accepted invalid test output")
			}
		})
	}
}

func TestProcessFailureAndAbsentTest(t *testing.T) {
	if err := checkTestEvents(strings.NewReader(goodEvents()), errors.New("exit status 1")); err == nil {
		t.Fatal("passing JSON concealed process failure")
	}
	var missing strings.Builder
	for _, line := range strings.Split(goodEvents(), "\n") {
		if line != "" && !strings.Contains(line, requiredTests[0]) {
			missing.WriteString(line + "\n")
		}
	}
	if err := checkTestEvents(strings.NewReader(missing.String()), nil); err == nil {
		t.Fatal("absent named test accepted")
	}
}

func TestEffectiveProfile(t *testing.T) {
	values := map[string]string{"GOVERSION": "go1.27.3"}
	for k, v := range requiredEnvironment {
		values[k] = v
	}
	values["GOENV"] = "" // disabled file path, as reported by go env
	if err := checkToolchain(values); err != nil {
		t.Fatal(err)
	}
	values["GOENV"] = "/untrusted/goenv"
	if err := checkToolchain(values); err == nil {
		t.Fatal("enabled goenv accepted")
	}
}

func TestRawExperimentAliases(t *testing.T) {
	for _, raw := range []string{"", "greenteagc", "none", "nogreenteagc", "greenteagc,none", "greenteagc,greenteagc", "greenteagc,arenas", " greenteagc", "greenteagc ", "GREENTEAGC"} {
		values := map[string]string{"GOVERSION": "go1.27.3"}
		for k, v := range requiredEnvironment {
			values[k] = v
		}
		values["GOEXPERIMENT"] = raw
		want := raw == "" || raw == "greenteagc"
		if err := checkEnvironment(func(k string) string { return values[k] }); (err == nil) != want {
			t.Errorf("raw %q environment result %v", raw, err)
		}
		values["GOENV"] = ""
		if err := checkToolchain(values); (err == nil) != want {
			t.Errorf("raw %q effective result %v", raw, err)
		}
		if values["GOEXPERIMENT"] != raw {
			t.Fatal("raw metadata normalized")
		}
	}
	for _, key := range []string{"GOVERSION", "GOOS", "GOARCH", "GOFLAGS"} {
		values := map[string]string{"GOVERSION": "go1.27.3"}
		for k, v := range requiredEnvironment {
			values[k] = v
		}
		values["GOENV"] = ""
		values["GOEXPERIMENT"] = "greenteagc"
		values[key] = "unsupported"
		if err := checkToolchain(values); err == nil {
			t.Fatalf("alias enabled unsupported %s", key)
		}
	}
}

func TestAuditedSourceManifestIncludesAliasControls(t *testing.T) {
	var manifest map[string]string
	if err := json.Unmarshal(sourceManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 15 {
		t.Fatalf("source pin count %d", len(manifest))
	}
	for _, name := range []string{"internal/buildcfg/exp.go", "internal/buildcfg/cfg.go", "cmd/go/internal/cfg/cfg.go", "internal/goexperiment/exp_greenteagc_on.go"} {
		if len(manifest[name]) != 64 {
			t.Fatalf("missing controlling source pin %s", name)
		}
	}
}
