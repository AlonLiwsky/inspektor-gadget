// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime/debug"
	"testing"
)

func fixtureModule() selectedModule {
	return selectedModule{Path: gadgetModule, Version: "v0.0.0-20261030000000-123456789abc", Sum: "h1:original", Replace: &selectedModule{Path: "github.com/kubescape/inspektor-gadget", Version: "v0.0.0-20261030000000-abcdef123456", Sum: "h1:fork"}}
}

func TestConsumerVersionedFork(t *testing.T) {
	good := fixtureModule()
	if err := checkSelectedModule(good); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*selectedModule){
		func(m *selectedModule) { m.Main = true }, func(m *selectedModule) { m.Version = "" }, func(m *selectedModule) { m.Replace.Version = "" }, func(m *selectedModule) { m.Replace.Path = "../fork" }, func(m *selectedModule) { m.Replace.Sum = "" }, func(m *selectedModule) { m.Path = "other/package" },
	} {
		bad := fixtureModule()
		mutate(&bad)
		if err := checkSelectedModule(bad); err == nil {
			t.Fatal("accepted invalid module", bad)
		}
	}
}

func fixtureBuildInfo() *debug.BuildInfo {
	m := fixtureModule()
	return &debug.BuildInfo{GoVersion: "go1.27.3", Deps: []*debug.Module{{Path: m.Path, Version: m.Version, Sum: m.Sum, Replace: &debug.Module{Path: m.Replace.Path, Version: m.Replace.Version, Sum: m.Replace.Sum}}}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "GOAMD64", Value: "v1"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "-buildmode", Value: "exe"}, {Key: "-compiler", Value: "gc"}, {Key: "-ldflags", Value: "-s -w -X github.com/armosec/private-node-agent/pkg/version.Version=1.2"}}}
}

func TestConsumerBinaryCompatibility(t *testing.T) {
	profile := map[string]string{"GOEXPERIMENT": ""}
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, fixtureBuildInfo(), fixtureModule(), profile); err != nil {
		t.Fatal(err)
	}
	for _, s := range []debug.BuildSetting{{Key: "-race", Value: "true"}, {Key: "-trimpath", Value: "true"}, {Key: "-pgo", Value: "default.pgo"}, {Key: "-tags", Value: "custom"}, {Key: "-gcflags", Value: "all=-N"}, {Key: "GOEXPERIMENT", Value: "nogreenteagc"}, {Key: "-ldflags", Value: "-linkmode=external"}, {Key: "-cover", Value: "true"}, {Key: "unknown", Value: "x"}} {
		b := fixtureBuildInfo()
		b.Settings = append(b.Settings, s)
		if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), profile); err == nil {
			t.Fatal("accepted unsupported binary setting", s)
		}
	}
	for _, mutate := range []func(*debug.BuildInfo){func(b *debug.BuildInfo) { b.GoVersion = "go1.27.4" }, func(b *debug.BuildInfo) { b.Deps[0].Replace.Version = "v0.1.0" }, func(b *debug.BuildInfo) { b.Deps = nil }, func(b *debug.BuildInfo) { b.Settings[1].Value = "arm64" }} {
		b := fixtureBuildInfo()
		mutate(b)
		if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), profile); err == nil {
			t.Fatal("accepted incompatible binary")
		}
	}
}

func TestConsumerLinkerOverrides(t *testing.T) {
	for _, raw := range []string{"", "-s -w", `-s -w -X 'github.com/armosec/private-node-agent/pkg/version.BuildTime=2026-10-30 12:00:00'`} {
		if err := checkLinkerFlags(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"-X", "-X model.Revision=forged", "-X github.com/armosec/private-node-agent/pkg/version.Other=x", "-X 'unterminated", "-X 'github.com/armosec/private-node-agent/pkg/version.Version=v1'junk", "-extldflags=-O2"} {
		if err := checkLinkerFlags(raw); err == nil {
			t.Fatal("accepted linker flag", raw)
		}
	}
}

func TestConsumerCommandIdentity(t *testing.T) {
	for _, target := range []string{"./cmd/node", "./"} {
		if err := checkCommandTarget(target); err != nil {
			t.Fatal(target, err)
		}
	}
	for _, target := range []string{"./cmd/main.go", "", "-tags=x", "./...", "./cmd/main.go ./other.go", "../main.go", "./../main.go", "/main.go", "./cmd\\main.go"} {
		if err := checkCommandTarget(target); err == nil {
			t.Fatal("accepted target", target)
		}
	}
	c := consumerCommand{ImportPath: "example.org/consumer/cmd/node", MainModule: "example.org/consumer"}
	b := &debug.BuildInfo{Path: c.ImportPath, Main: debug.Module{Path: c.MainModule, Version: "(devel)"}}
	if err := checkBinaryCommand(b, c); err != nil {
		t.Fatal(err)
	}
	b.Path = "example.org/consumer/cmd/other"
	if err := checkBinaryCommand(b, c); err == nil {
		t.Fatal("wrong command accepted")
	}
	b.Path = c.ImportPath
	b.Main.Path = "other"
	if err := checkBinaryCommand(b, c); err == nil {
		t.Fatal("wrong main accepted")
	}
	c.ImportPath = "example.org/consumer/cmd/node"
	b.Path = "command-line-arguments"
	b.Main = debug.Module{}
	if err := checkBinaryCommand(b, c); err == nil {
		t.Fatal("file binary accepted")
	}
}

func TestConsumerDuplicateBinaryMetadata(t *testing.T) {
	b := fixtureBuildInfo()
	b.Deps = append(b.Deps, b.Deps[0])
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), map[string]string{}); err == nil {
		t.Fatal("duplicate module accepted")
	}
	b = fixtureBuildInfo()
	b.Settings = append(b.Settings, b.Settings[0])
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), map[string]string{}); err == nil {
		t.Fatal("duplicate setting accepted")
	}
	b = fixtureBuildInfo()
	b.Deps[0].Sum = ""
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), map[string]string{}); err != nil {
		t.Fatal("missing original replaced-module sum should be accepted", err)
	}
	b = fixtureBuildInfo()
	b.Settings = append(b.Settings, debug.BuildSetting{Key: "GOEXPERIMENT", Value: "greenteagc"})
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), map[string]string{"GOEXPERIMENT": "greenteagc"}); err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryInfo([]debug.Module{moduleIdentity(fixtureModule())}, b, fixtureModule(), map[string]string{"GOEXPERIMENT": ""}); err == nil {
		t.Fatal("lost raw experiment distinction")
	}
}
