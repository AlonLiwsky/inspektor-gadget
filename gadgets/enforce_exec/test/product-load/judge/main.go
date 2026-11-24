// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command judge decides the product object-load run (test/product-load).
//
//	judge check -expected expected.tsv -results DIR -kernels K,... -profiles P,...|- [-rows N] [-out results.tsv]
//	judge row   -stream FILE -test NAME -status pass|fail [-detail TEXT]
//	judge end   -stream FILE
//
// check compares the test2json streams under DIR (<kernel>/<step>__<profile>.json)
// and each <kernel>/infra.tsv with the selected expected rows. It exits 0
// only if every expected row has exactly one pass and no skip or fail, no
// unexpected test or stream appears, no stream is empty or truncated and
// every infrastructure step exited 0. With -rows the selection must hold
// exactly N rows (the full run pins it). Its exit code is the job result.
//
// row and end write the harness checks (identity, raw load, hygiene) as
// test2json events, so they are judged like Go tests: row appends one
// check's run, output and result; end appends the package result (fail if
// any row failed). A harness that dies before end leaves a truncated stream,
// which check rejects.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func check(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	expected := fs.String("expected", "", "expected.tsv")
	results := fs.String("results", "", "results directory")
	kernels := fs.String("kernels", "", "comma-separated kernel groups to judge (e.g. build,kernel)")
	profiles := fs.String("profiles", "", "comma-separated profiles to judge (e.g. 64,128,256,512)")
	out := fs.String("out", "", "write every verdict as TSV here")
	want := fs.Int("rows", 0, "require exactly this many selected rows (0: no pin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *expected == "" || *results == "" {
		return errors.New("-expected and -results are required")
	}
	f, err := os.Open(*expected)
	if err != nil {
		return err
	}
	rows, err := parseExpected(f)
	f.Close()
	if err != nil {
		return err
	}
	ks := list(*kernels)
	if rows, err = selectRows(rows, ks, list(*profiles)); err != nil {
		return err
	}
	if *want != 0 && len(rows) != *want {
		return fmt.Errorf("RED: the selection holds %d expected rows, the run pins %d", len(rows), *want)
	}
	scope := fmt.Sprintf("kernels %s, profiles %s", strings.Join(ks, ","), *profiles)
	verdicts := judge(*results, rows, ks)
	var tsv strings.Builder
	fmt.Fprintf(&tsv, "# judged: %s, %d expected rows\n", scope, len(rows))
	tsv.WriteString("# kernel\tstep\ttest\tprofile\tstatus\tdetail\n")
	pass, fail := 0, 0
	for _, v := range verdicts {
		fmt.Fprintf(&tsv, "%s\t%s\t%s\t%s\t%s\t%s\n", v.Row.Kernel, v.Row.Step, v.Row.Test, v.Row.Profile, v.Status, strings.ReplaceAll(v.Detail, "\t", " "))
		if v.Status == "PASS" {
			pass++
		} else {
			fail++
			fmt.Fprintf(stdout, "FAIL %s %s %s %s: %s\n", v.Row.Kernel, v.Row.Step, v.Row.Test, v.Row.Profile, v.Detail)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(tsv.String()), 0o644); err != nil {
			return err
		}
	}
	if fail != 0 || pass != len(rows) {
		return fmt.Errorf("RED (%s): %d of %d expected rows PASS, %d FAIL", scope, pass, len(rows), fail)
	}
	fmt.Fprintf(stdout, "GREEN (%s): exactly %d unique PASS rows, FAIL = 0\n", scope, pass)
	return nil
}

// appendEvents appends test2json events to path.
func appendEvents(path string, events ...event) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func emitRow(args []string) error {
	fs := flag.NewFlagSet("row", flag.ContinueOnError)
	path := fs.String("stream", "", "stream file")
	test := fs.String("test", "", "check name")
	status := fs.String("status", "", "pass or fail")
	detail := fs.String("detail", "", "evidence line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *test == "" || (*status != "pass" && *status != "fail") {
		return errors.New("-stream, -test and -status pass|fail are required")
	}
	now := time.Now().UTC()
	return appendEvents(*path,
		event{Time: now, Action: "run", Test: *test},
		event{Time: now, Action: "output", Test: *test, Output: *detail + "\n"},
		event{Time: now, Action: *status, Test: *test})
}

func emitEnd(args []string) error {
	fs := flag.NewFlagSet("end", flag.ContinueOnError)
	path := fs.String("stream", "", "stream file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("-stream is required")
	}
	action := "pass"
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	tests, err := readStreamRows(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	if len(tests) == 0 {
		action = "fail"
	}
	for _, o := range tests {
		if o.fail > 0 || o.skip > 0 || o.pass != 1 {
			action = "fail"
		}
	}
	return appendEvents(*path, event{Time: time.Now().UTC(), Action: action})
}

// readStreamRows reads a harness stream before its package result.
func readStreamRows(r io.Reader) (map[string]*outcome, error) {
	tests := map[string]*outcome{}
	dec := json.NewDecoder(r)
	for {
		var e event
		if err := dec.Decode(&e); err == io.EOF {
			return tests, nil
		} else if err != nil {
			return tests, err
		}
		if e.Test == "" {
			return tests, errors.New("stream already has a package result")
		}
		o := tests[e.Test]
		if o == nil {
			o = &outcome{}
			tests[e.Test] = o
		}
		switch e.Action {
		case "pass":
			o.pass++
		case "fail":
			o.fail++
		case "skip":
			o.skip++
		}
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: judge check|row|end [args]")
	}
	switch args[0] {
	case "check":
		return check(args[1:], stdout)
	case "row":
		return emitRow(args[1:])
	case "end":
		return emitEnd(args[1:])
	}
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
