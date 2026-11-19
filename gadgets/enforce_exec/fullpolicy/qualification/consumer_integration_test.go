// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is a controlled file-proxy fixture, NOT a published dependency or actual
// consumer release. It proves MVS selection/consumer-root execution mechanics.
func TestConsumerProxyAndBinaryFixture(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("positive source corroboration requires audited local toolchain")
	}
	for k, v := range requiredEnvironment {
		t.Setenv(k, v)
	}
	t.Setenv("GOFIPS140", "off")
	temp := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(temp, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	proxy := filepath.Join(temp, "proxy")
	consumer := filepath.Join(temp, "consumer")
	for _, dir := range []string{proxy, consumer, filepath.Join(consumer, "cmd")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GOMODCACHE", filepath.Join(temp, "modcache"))
	version := "v0.0.0-20261030000000-abcdef123456"
	fork := "example.org/fixture/ig"
	module := []byte("module " + gadgetModule + "\n\ngo 1.25.0\n")
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	add := func(name string, data []byte) {
		w, err := zw.Create(fork + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add("go.mod", module)
	source, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(source, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		// Keep the actual 15 model tests; unrelated kernel integration tests
		// require external modules and are outside this offline proxy fixture.
		if strings.HasSuffix(path, "_test.go") && filepath.Base(path) != "workspace_syntax_test.go" {
			return nil
		}
		rel, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		add("gadgets/enforce_exec/fullpolicy/"+filepath.ToSlash(rel), b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	proxyDir := filepath.Join(proxy, fork, "@v")
	if err = os.MkdirAll(proxyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{version + ".mod": module, version + ".zip": buffer.Bytes(), version + ".info": []byte(fmt.Sprintf(`{"Version":%q,"Time":"2026-10-30T00:00:00Z"}`, version)), "list": []byte(version + "\n")} {
		if err = os.WriteFile(filepath.Join(proxyDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Include a real linked non-IG dependency and an unlinked graph member.
	for _, name := range []string{"dep", "unlinked"} {
		path := "example.org/fixture/" + name
		modData := []byte("module " + path + "\n\ngo 1.25.0\n")
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		for file, data := range map[string][]byte{"go.mod": modData, "value.go": []byte("package " + name + "\nfunc Value() int { return 7 }\n")} {
			entry, e := writer.Create(path + "@v1.0.0/" + file)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = entry.Write(data); e != nil {
				t.Fatal(e)
			}
		}
		if e := writer.Close(); e != nil {
			t.Fatal(e)
		}
		dir := filepath.Join(proxy, path, "@v")
		if e := os.MkdirAll(dir, 0o755); e != nil {
			t.Fatal(e)
		}
		for file, data := range map[string][]byte{"v1.0.0.mod": modData, "v1.0.0.zip": archive.Bytes(), "v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-30T00:00:00Z"}`), "list": []byte("v1.0.0\n")} {
			if e := os.WriteFile(filepath.Join(dir, file), data, 0o600); e != nil {
				t.Fatal(e)
			}
		}
	}
	mod := fmt.Sprintf("module example.org/consumer\n\ngo 1.25.0\n\nrequire %s %s\nreplace %s => %s %s\n", gadgetModule, version, gadgetModule, fork, version)
	mod += "require example.org/fixture/dep v1.0.0\nrequire example.org/fixture/unlinked v1.0.0\n"
	if err = os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(mod), 0o600); err != nil {
		t.Fatal(err)
	}
	main := []byte("package main\nimport (\"fmt\"; p \"" + testedPackage + "\"; \"example.org/fixture/dep\")\nfunc main(){fmt.Println(p.MaxPolicies,dep.Value())}\n")
	if err = os.WriteFile(filepath.Join(consumer, "cmd/main.go"), main, 0o600); err != nil {
		t.Fatal(err)
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goPath, "mod", "download", "all")
	cmd.Dir = consumer
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture download: %s %v", out, e)
	}
	if _, err = snapshotConsumer(goPath, consumer, "./cmd/main.go"); err == nil {
		t.Fatal("file command unexpectedly has release evidence")
	}
	pre := filepath.Join(temp, "pre.json")
	var events, logs bytes.Buffer
	if err = runConsumer(goPath, consumer, "./cmd", "", "", pre, &events, &logs); err != nil {
		t.Fatalf("%v\n%s\n%s", err, events.String(), logs.String())
	}
	r, _, err := readPrebuild(pre)
	if err != nil {
		t.Fatal(err)
	}
	if r.Snapshot.Package.Module.Replace.Path != fork || r.Snapshot.Command.ImportPath != "example.org/consumer/cmd" {
		t.Fatal("wrong fixture selection")
	}
	binary := filepath.Join(temp, "app")
	cmd = exec.Command(goPath, "build", "-o", binary, "-ldflags=-s -w", "./cmd")
	cmd.Dir = consumer
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture build: %s %v", out, e)
	}
	bound := filepath.Join(temp, "build.json")
	if err = runConsumer(goPath, consumer, "./cmd", pre, binary, bound, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bound)
	if err != nil {
		t.Fatal(err)
	}
	var b consumerReport
	if err = json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	for _, key := range resolverKeys {
		if _, exists := b.Snapshot.Profile[key]; exists {
			t.Fatal("raw resolver key persisted", key)
		}
		if !validHash(b.Snapshot.ResolverHashes[key]) {
			t.Fatal("missing resolver digest", key)
		}
	}
	if b.Snapshot.ResolverHashes["GOPROXY"] != hashBytes([]byte(os.Getenv("GOPROXY"))) {
		t.Fatal("resolver equality commitment changed")
	}
	if len(r.Snapshot.Modules) != 3 || len(b.Binary.BuildInfo.Deps) != 2 {
		t.Fatal("did not compare a proper linked subset of complete selected MVS")
	}
	if b.Phase != "BUILD" || b.ArtifactLinkage != "LINKED_BINARY_ONLY" || b.NativeBudgetQualified == nil || *b.NativeBudgetQualified || string(b.CompleteModelRevision) != "null" || b.Runner.SourceLinkage != "UNPROVEN" || b.BindRunner == nil {
		t.Fatal("evidence escalated")
	}
	// Editing the declared command, consumer module, graph/tool/source digest in
	// a prebuild record must never be accepted merely because tests once passed.
	for name, mutate := range map[string]func(*consumerReport){"tool": func(r *consumerReport) { r.Snapshot.ToolHashes["bin/go"] = "changed" }, "source": func(r *consumerReport) { r.Snapshot.Inputs["fullpolicy/workspace_syntax.go"] = "changed" }, "module": func(r *consumerReport) { r.Snapshot.Inputs["consumer/go.mod"] = "changed" }, "graph": func(r *consumerReport) { r.Snapshot.GraphHash = "changed" }} {
		r, _, err := readPrebuild(pre)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&r)
		bad := filepath.Join(temp, name+".json")
		if err = writeReport(bad, r); err != nil {
			t.Fatal(err)
		}
		if err = runConsumer(goPath, consumer, "./cmd", bad, binary, filepath.Join(temp, name+"-bound.json"), io.Discard, io.Discard); err == nil {
			t.Fatal("accepted changed", name)
		}
	}
	// Missing selected command source and a changed actual model source are
	// refused even though the module version/graph remain unchanged.
	selectedDir := r.Snapshot.Package.Dir
	selectedQ := filepath.Join(selectedDir, "qualification/main.go")
	qData, e := os.ReadFile(selectedQ)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Dir(selectedQ), 0o755); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(selectedQ); e != nil {
		t.Fatal(e)
	}
	if _, e = snapshotConsumer(goPath, consumer, "./cmd"); e == nil {
		t.Fatal("missing selected qualification source accepted")
	}
	if e = os.WriteFile(selectedQ, qData, 0o444); e != nil {
		t.Fatal(e)
	}
	selectedModel := filepath.Join(selectedDir, "workspace_syntax.go")
	modelData, e := os.ReadFile(selectedModel)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(selectedModel, 0o644); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(selectedModel, append(modelData, []byte("\n// changed selected model\n")...), 0o644); e != nil {
		t.Fatal(e)
	}
	if e = runConsumer(goPath, consumer, "./cmd", pre, binary, filepath.Join(temp, "changed-model.json"), io.Discard, io.Discard); e == nil {
		t.Fatal("changed actual model accepted")
	}
	if e = os.WriteFile(selectedModel, modelData, 0o444); e != nil {
		t.Fatal(e)
	}
	// Actual command input mutation is refused even though binary metadata is unchanged.
	if err = os.WriteFile(filepath.Join(consumer, "cmd/main.go"), append(main, []byte("\n// changed command input\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = runConsumer(goPath, consumer, "./cmd", pre, binary, filepath.Join(temp, "changed-command.json"), io.Discard, io.Discard); err == nil {
		t.Fatal("changed command source accepted")
	}
	if err = os.WriteFile(filepath.Join(consumer, "cmd/main.go"), main, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(consumer, "cmd/default.pgo"), []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshotConsumer(goPath, consumer, "./cmd"); err == nil {
		t.Fatal("accepted implicit PGO")
	}
}
