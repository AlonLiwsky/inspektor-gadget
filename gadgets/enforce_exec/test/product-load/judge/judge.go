// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// row is one expected result: a test (or harness check) in one stream.
type row struct {
	Kernel, Step, Test, Profile string
}

// stream identifies one test2json file: <results>/<kernel>/<step>__<profile>.json.
type stream struct {
	Kernel, Step, Profile string
}

func (r row) stream() stream { return stream{r.Kernel, r.Step, r.Profile} }

func (s stream) path(results string) string {
	return filepath.Join(results, s.Kernel, s.Step+"__"+s.Profile+".json")
}

// event is the subset of a test2json event the judge reads.
type event struct {
	Time    time.Time `json:",omitempty"`
	Action  string
	Package string  `json:",omitempty"`
	Test    string  `json:",omitempty"`
	Output  string  `json:",omitempty"`
	Elapsed float64 `json:",omitempty"`
}

// verdict is one judged row (or a stream- or run-level finding).
type verdict struct {
	Row    row
	Status string // PASS or FAIL
	Detail string
}

// parseExpected reads expected.tsv: kernel, step, test, profile per line
// ("-" for no profile); '#' starts a comment line. A duplicate row is an
// error (the count must be exact).
func parseExpected(r io.Reader) ([]row, error) {
	var rows []row
	seen := map[row]bool{}
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("expected line %d: %d tab-separated fields, want 4 (kernel step test profile)", n, len(f))
		}
		for i, v := range f {
			// kernel, step and profile name a stream file; a test name
			// may hold '/' (a subtest).
			if v == "" || strings.ContainsAny(v, " \\") || i != 2 && (strings.Contains(v, "/") || strings.Contains(v, "__")) {
				return nil, fmt.Errorf("expected line %d: bad field %q", n, v)
			}
		}
		r := row{f[0], f[1], f[2], f[3]}
		if seen[r] {
			return nil, fmt.Errorf("expected line %d: duplicate row %v", n, r)
		}
		seen[r] = true
		rows = append(rows, r)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("expected list is empty")
	}
	return rows, nil
}

// selectRows keeps the rows of the judged kernels and profiles (the
// profile set is configuration); a "-" profile row is always kept. The
// profile list "-" alone judges only profile-agnostic rows (e.g. the build
// group). Every judged kernel and profile must have selected rows, so a typo
// or a mismatched selection can never judge nothing.
func selectRows(rows []row, kernels, profiles []string) ([]row, error) {
	if len(kernels) == 0 || len(profiles) == 0 {
		return nil, errors.New("-kernels and -profiles are required")
	}
	agnostic := len(profiles) == 1 && profiles[0] == "-"
	var out []row
	for _, r := range rows {
		if slices.Contains(kernels, r.Kernel) && (r.Profile == "-" || !agnostic && slices.Contains(profiles, r.Profile)) {
			out = append(out, r)
		}
	}
	for _, k := range kernels {
		if !slices.ContainsFunc(out, func(r row) bool { return r.Kernel == k }) {
			return nil, fmt.Errorf("kernel %q has no expected rows", k)
		}
	}
	if !agnostic {
		for _, p := range profiles {
			if p == "-" || !slices.ContainsFunc(out, func(r row) bool { return r.Profile == p }) {
				return nil, fmt.Errorf("profile %q has no expected rows in the judged kernels", p)
			}
		}
	}
	return out, nil
}

// outcome is what one stream says about each test.
type outcome struct {
	pass, fail, skip int
	run              bool
	output           strings.Builder
}

// readStream parses one test2json stream. It fails on an empty stream, a
// line that is not a JSON event, a missing package-level result (a
// truncated stream), a package-level fail or skip, and a test that started
// but never ended.
func readStream(r io.Reader) (map[string]*outcome, error) {
	tests := map[string]*outcome{}
	get := func(name string) *outcome {
		o := tests[name]
		if o == nil {
			o = &outcome{}
			tests[name] = o
		}
		return o
	}
	var final string
	lines := 0
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1<<20), 64<<20)
	for s.Scan() {
		raw := bytes.TrimSpace(s.Bytes())
		if len(raw) == 0 {
			continue
		}
		lines++
		var e event
		if err := json.Unmarshal(raw, &e); err != nil || e.Action == "" {
			return nil, fmt.Errorf("line %d is not a test2json event: %.120q", lines, raw)
		}
		if final != "" {
			return nil, fmt.Errorf("event after the package result %q (two runs in one stream?)", final)
		}
		if e.Test == "" {
			switch e.Action {
			case "pass", "fail", "skip":
				final = e.Action
			}
			continue
		}
		o := get(e.Test)
		switch e.Action {
		case "run":
			o.run = true
		case "pass":
			o.pass++
		case "fail":
			o.fail++
		case "skip":
			o.skip++
		case "output":
			if o.output.Len() < 4096 {
				o.output.WriteString(e.Output)
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	switch {
	case lines == 0:
		return nil, errors.New("empty stream")
	case final == "":
		return nil, errors.New("truncated stream: no package result")
	case final != "pass":
		return tests, fmt.Errorf("package result %q", final)
	}
	for name, o := range tests {
		if o.run && o.pass+o.fail+o.skip == 0 {
			return tests, fmt.Errorf("truncated stream: test %s started and never ended", name)
		}
	}
	return tests, nil
}

// readInfra reads <results>/<kernel>/infra.tsv (name, exit code, detail):
// the launcher, transfer, guest and cleanup steps. It must exist, be
// non-empty and every code must be 0: an infrastructure failure is never a
// pass.
func readInfra(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("infra record: %v", err)}
	}
	var bad []string
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		f := strings.SplitN(line, "\t", 3)
		if len(f) < 2 {
			bad = append(bad, fmt.Sprintf("infra line %q malformed", line))
			continue
		}
		if code, err := strconv.Atoi(f[1]); err != nil || code != 0 {
			bad = append(bad, fmt.Sprintf("infra %s exited %s: %s", f[0], f[1], strings.Join(f[2:], "")))
		}
	}
	if n == 0 {
		bad = append(bad, "infra record is empty")
	}
	return bad
}

// judge compares the results directory with the selected rows. It returns
// one verdict per expected row plus one FAIL verdict per stream- or
// run-level finding (an unexpected test or stream, a broken stream, an
// infrastructure failure). The run passes only when every verdict is PASS.
func judge(results string, rows []row, kernels []string) []verdict {
	var out []verdict
	fail := func(r row, format string, args ...any) {
		out = append(out, verdict{r, "FAIL", fmt.Sprintf(format, args...)})
	}
	byStream := map[stream][]row{}
	var order []stream
	for _, r := range rows {
		if _, ok := byStream[r.stream()]; !ok {
			order = append(order, r.stream())
		}
		byStream[r.stream()] = append(byStream[r.stream()], r)
	}
	for _, k := range kernels {
		for _, msg := range readInfra(filepath.Join(results, k, "infra.tsv")) {
			fail(row{k, "infra", "-", "-"}, "%s", msg)
		}
		// Every stream on disk must be expected.
		files, _ := filepath.Glob(filepath.Join(results, k, "*.json"))
		for _, f := range files {
			step, profile, ok := strings.Cut(strings.TrimSuffix(filepath.Base(f), ".json"), "__")
			if _, expected := byStream[stream{k, step, profile}]; !ok || !expected {
				fail(row{k, "unexpected-stream", filepath.Base(f), "-"}, "stream %s is not in the expected list", f)
			}
		}
	}
	for _, s := range order {
		expected := byStream[s]
		f, err := os.Open(s.path(results))
		if err != nil {
			for _, r := range expected {
				fail(r, "missing stream: %v", err)
			}
			continue
		}
		tests, err := readStream(f)
		f.Close()
		streamErr := ""
		if err != nil {
			streamErr = err.Error()
			fail(row{s.Kernel, s.Step, "(stream)", s.Profile}, "%s: %s", s.path(results), streamErr)
		}
		for _, r := range expected {
			o := tests[r.Test]
			switch {
			case o == nil:
				fail(r, "missing row%s", suffix(streamErr))
			case o.skip > 0:
				fail(r, "skipped (a skip is a failure): %s", firstLine(o.output.String()))
			case o.fail > 0:
				fail(r, "failed: %s", firstLine(o.output.String()))
			case o.pass != 1:
				fail(r, "%d passes, want exactly 1", o.pass)
			case streamErr != "":
				fail(r, "passed in a broken stream: %s", streamErr)
			default:
				out = append(out, verdict{r, "PASS", ""})
			}
			delete(tests, r.Test)
		}
		for name, o := range tests {
			fail(row{s.Kernel, s.Step, name, s.Profile}, "unexpected test (pass=%d fail=%d skip=%d)", o.pass, o.fail, o.skip)
		}
	}
	return out
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// firstLine is the most telling line of a test's output: the first one
// that is not an === or --- marker.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "===") && !strings.HasPrefix(l, "---") {
			if len(l) > 200 {
				l = l[:200]
			}
			return l
		}
	}
	return ""
}
