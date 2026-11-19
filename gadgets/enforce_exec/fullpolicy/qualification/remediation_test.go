// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolverSecretsNeverPersist(t *testing.T) {
	secret := "SYNTHETIC_RESOLVER_SECRET"
	profile := map[string]string{"GOVERSION": "go1.27.3", "GOPROXY": "https://user:" + secret + "@host/path?token=" + secret + ",https://other/" + secret, "GOSUMDB": "sumdb https://host/" + secret, "GOPRIVATE": secret, "GONOPROXY": secret, "GONOSUMDB": secret, "GOMODCACHE": "/cache/" + secret}
	hashes := publishResolverHashes(profile)
	data, err := json.Marshal(struct{ Profile, Hashes map[string]string }{profile, hashes})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || len(hashes) != 6 || profile["GOVERSION"] != "go1.27.3" {
		t.Fatal("raw resolver input persisted", string(data))
	}
	if hashes["GOPROXY"] != hashBytes([]byte("https://user:"+secret+"@host/path?token="+secret+",https://other/"+secret)) {
		t.Fatal("did not hash exact resolver input")
	}
	for _, raw := range []string{"go: https://user:" + secret + "@host: 401 Unauthorized", "stat /" + secret + ": directory not found", "unknown failure " + secret} {
		safe := safeGoDiagnostic([]byte(raw))
		if strings.Contains(safe, secret) || safe == "" {
			t.Fatal("unsafe/empty diagnostic", safe)
		}
	}
	if got := safeGoDiagnostic([]byte("stat /some/path: directory not found")); !strings.Contains(got, "path") {
		t.Fatal("useful failure category missing", got)
	}
}

func TestEveryLinkedDependencyMatchesMVS(t *testing.T) {
	selected := []debug.Module{{Path: "example.org/dep", Version: "v1.0.0", Sum: "h1:dep"}, {Path: "example.org/unlinked", Version: "v2.0.0", Sum: "h1:unused"}}
	good := []*debug.Module{{Path: "example.org/dep", Version: "v1.0.0", Sum: "h1:dep"}}
	if err := checkLinkedModules(good, selected); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*debug.Module{nil, {Path: "unknown", Version: "v1.0.0", Sum: "h1:dep"}, {Path: "example.org/dep", Version: "v1.0.1", Sum: "h1:dep"}, {Path: "example.org/dep", Version: "v1.0.0", Sum: "h1:wrong"}, {Path: "example.org/dep", Version: "v1.0.0", Sum: "h1:dep", Replace: &debug.Module{Path: "local"}}} {
		if err := checkLinkedModules([]*debug.Module{m}, selected); err == nil {
			t.Fatal("accepted mismatched linked module", m)
		}
	}
	selected[0].Replace = &debug.Module{Path: "example.org/fork", Version: "v1.2.0", Sum: "h1:fork"}
	replaced := &debug.Module{Path: "example.org/dep", Version: "v1.0.0", Replace: &debug.Module{Path: "example.org/fork", Version: "v1.2.0", Sum: "h1:fork"}}
	if err := checkLinkedModules([]*debug.Module{replaced}, selected); err != nil {
		t.Fatal("replaced original sum omission rejected", err)
	}
	for _, mutate := range []func(*debug.Module){func(m *debug.Module) { m.Replace.Path = "other" }, func(m *debug.Module) { m.Replace.Version = "v2.0.0" }, func(m *debug.Module) { m.Replace.Sum = "h1:wrong" }} {
		m := *replaced
		r := *replaced.Replace
		m.Replace = &r
		mutate(&m)
		if err := checkLinkedModules([]*debug.Module{&m}, selected); err == nil {
			t.Fatal("replacement mismatch accepted")
		}
	}
	if err := checkLinkedModules([]*debug.Module{replaced, replaced}, selected); err == nil {
		t.Fatal("duplicate linked dependency accepted")
	}
}

func TestSafeRealGoFailure(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Setenv("GOPROXY", "https://user:SYNTHETIC_RESOLVER_SECRET@invalid/path?token=SYNTHETIC_RESOLVER_SECRET")
	_, err = commandOutput(goPath, ".", os.Environ(), "list", "-json", "./SYNTHETIC_RESOLVER_SECRET-nonexistent")
	if err == nil || !strings.Contains(err.Error(), "selected path is unavailable") || strings.Contains(err.Error(), "SYNTHETIC_RESOLVER_SECRET") {
		t.Fatal("missing safe concrete failure category", err)
	}
}

func TestQualificationDiagnosticChild(t *testing.T) {
	mode := os.Getenv("QUALIFICATION_DIAGNOSTIC_CHILD")
	if mode == "" {
		return
	}
	secret := "SYNTHETIC_RESOLVER_SECRET"
	raw := goodEvents()
	run := fmt.Sprintf(`{"Action":"run","Package":%q,"Test":%q}`, testedPackage, requiredTests[0])
	output := fmt.Sprintf(`{"Action":"output","Package":%q,"Test":%q,"Output":%q}`, testedPackage, requiredTests[0], secret)
	raw = strings.Replace(raw, run, run+"\n"+output, 1)
	switch mode {
	case "skip":
		raw = strings.Replace(raw, `"Action":"pass"`, `"Action":"skip"`, 1)
	case "malformed":
		raw += secret
	}
	fmt.Fprint(os.Stdout, raw)
	fmt.Fprintln(os.Stderr, "stat /"+secret+": directory not found")
	if mode == "fail" {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestSafeTestStreamsPreserveOracle(t *testing.T) {
	for _, mode := range []string{"success", "skip", "malformed", "fail"} {
		t.Run(mode, func(t *testing.T) {
			c := exec.Command(os.Args[0], "-test.run=^TestQualificationDiagnosticChild$")
			c.Env = append(os.Environ(), "QUALIFICATION_DIAGNOSTIC_CHILD="+mode)
			var events, logs bytes.Buffer
			err := runModelTests(c, &events, &logs)
			if (err == nil) != (mode == "success") {
				t.Fatal("outcome was hidden", err)
			}
			if strings.Contains(events.String()+logs.String()+fmt.Sprint(err), "SYNTHETIC_RESOLVER_SECRET") {
				t.Fatal("child output leaked secret")
			}
			if mode == "success" {
				if err = checkTestEvents(&events, nil); err != nil {
					t.Fatal("safe events lost structured outcomes", err)
				}
			}
		})
	}
}

func TestMainVersionIsObservedNotAssumed(t *testing.T) {
	c := consumerCommand{MainModule: "example.org/consumer", ImportPath: "example.org/consumer/cmd"}
	for _, version := range []string{"(devel)", "v0.3.294-0.20261029165939-a7d2920a581f+dirty", "v0.0.585-0.20261027173330-9e70a7e5f29f+dirty"} {
		b := &debug.BuildInfo{Path: c.ImportPath, Main: debug.Module{Path: c.MainModule, Version: version}}
		if err := checkBinaryCommand(b, c); err != nil {
			t.Fatal("valid observed main version refused", version, err)
		}
	}
	for _, mutate := range []func(*debug.BuildInfo){func(b *debug.BuildInfo) { b.Main.Version = "" }, func(b *debug.BuildInfo) { b.Main.Path = "" }, func(b *debug.BuildInfo) { b.Path = "other" }, func(b *debug.BuildInfo) { b.Main.Sum = "h1:wrong" }, func(b *debug.BuildInfo) { b.Main.Replace = &debug.Module{Path: "replacement"} }} {
		b := &debug.BuildInfo{Path: c.ImportPath, Main: debug.Module{Path: c.MainModule, Version: "(devel)"}}
		mutate(b)
		if err := checkBinaryCommand(b, c); err == nil {
			t.Fatal("invalid main identity accepted")
		}
	}
}

func TestBinaryPolicyChecksNonIGDependency(t *testing.T) {
	b := fixtureBuildInfo()
	b.Deps = append(b.Deps, &debug.Module{Path: "example.org/dep", Version: "v1.0.1", Sum: "h1:dep"})
	inventory := []debug.Module{moduleIdentity(fixtureModule()), {Path: "example.org/dep", Version: "v1.0.0", Sum: "h1:dep"}}
	if err := checkBinaryInfo(inventory, b, fixtureModule(), map[string]string{}); err == nil {
		t.Fatal("full binary policy bypassed non-IG version check")
	}
	b.Deps[1].Version = "v1.0.0"
	if err := checkBinaryInfo(inventory, b, fixtureModule(), map[string]string{}); err != nil {
		t.Fatal(err)
	}
}
