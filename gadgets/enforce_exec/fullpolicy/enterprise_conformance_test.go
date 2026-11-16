// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// These portable inputs and literal expected decisions are shared semantic
// vectors, not evidence that any backend acquires authoritative facts, mediates
// exec, commits roles, or qualifies a kernel. See the corpus README.
type enterpriseCorpus struct {
	Version int               `json:"version"`
	Groups  []enterpriseGroup `json:"groups"`
}

type enterpriseGroup struct {
	Name     string           `json:"name"`
	Policies []Policy         `json:"policies"`
	Cases    []enterpriseCase `json:"cases"`
}

type enterpriseCase struct {
	Name  string `json:"name"`
	Facts *Facts `json:"facts"`
	Want  struct {
		Decision        json.RawMessage `json:"decision"`
		EvaluationError *bool           `json:"evaluationError"`
	} `json:"want"`
	decision Decision
}

func decodeEnterpriseCorpus(data []byte) (enterpriseCorpus, error) {
	var corpus enterpriseCorpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return corpus, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err != nil {
			return corpus, fmt.Errorf("decode trailing data: %w", err)
		}
		return corpus, errors.New("expected one JSON document")
	}
	if corpus.Version != 1 || len(corpus.Groups) == 0 {
		return corpus, fmt.Errorf("require version 1 and nonempty groups")
	}
	groups := make(map[string]bool)
	for gi := range corpus.Groups {
		group := &corpus.Groups[gi]
		if group.Name == "" || groups[group.Name] || len(group.Policies) == 0 || len(group.Cases) == 0 {
			return corpus, fmt.Errorf("invalid or duplicate group %q", group.Name)
		}
		groups[group.Name] = true
		cases := make(map[string]bool)
		for ci := range group.Cases {
			c := &group.Cases[ci]
			if c.Name == "" || cases[c.Name] || c.Facts == nil || c.Want.EvaluationError == nil {
				return corpus, fmt.Errorf("invalid or duplicate case %q/%q", group.Name, c.Name)
			}
			cases[c.Name] = true
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(c.Want.Decision, &fields); err != nil {
				return corpus, fmt.Errorf("%s/%s decision: %w", group.Name, c.Name, err)
			}
			// Every Decision field is explicit, including false booleans. Adding a
			// field to the contract requires updating the corpus, not silently
			// accepting a missing field as its Go zero value.
			decisionType := reflect.TypeFor[Decision]()
			for i := range decisionType.NumField() {
				field := decisionType.Field(i)
				value, exists := fields[field.Name]
				if !exists || (field.Type.Kind() != reflect.Map && field.Type.Kind() != reflect.Slice && bytes.Equal(value, []byte("null"))) {
					return corpus, fmt.Errorf("%s/%s: missing decision field %s", group.Name, c.Name, field.Name)
				}
			}
			decisionDecoder := json.NewDecoder(bytes.NewReader(c.Want.Decision))
			decisionDecoder.DisallowUnknownFields()
			if err := decisionDecoder.Decode(&c.decision); err != nil {
				return corpus, fmt.Errorf("%s/%s decision: %w", group.Name, c.Name, err)
			}
			if (c.decision.Action != Allow && c.decision.Action != Deny) || (c.decision.Mode != Audit && c.decision.Mode != Enforce) {
				return corpus, fmt.Errorf("%s/%s: invalid expected action or mode", group.Name, c.Name)
			}
		}
	}
	return corpus, nil
}

// Only empty collections are representation-equivalent. In particular, Facts
// pointer presence and completeness flags are never normalized: unknown != false.
func normalizeEnterpriseDecision(d Decision) Decision {
	if len(d.Matches) == 0 {
		d.Matches = nil
	}
	if len(d.SetRoles) == 0 {
		d.SetRoles = nil
	}
	if len(d.AuditUnknown) == 0 {
		d.AuditUnknown = nil
	}
	if len(d.UncertainRoles) == 0 {
		d.UncertainRoles = nil
	}
	if len(d.RoleWrites) == 0 {
		d.RoleWrites = nil
	}
	return d
}

func TestEnterpriseDecisionCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/enterprise-conformance/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("find corpus: %v (%d files)", err, len(files))
	}
	groups := make(map[string]bool)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		corpus, err := decodeEnterpriseCorpus(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, group := range corpus.Groups {
			if groups[group.Name] {
				t.Fatalf("duplicate corpus group %q", group.Name)
			}
			groups[group.Name] = true
			for _, c := range group.Cases {
				t.Run(group.Name+"/"+c.Name, func(t *testing.T) {
					for order := range 4 {
						t.Run(fmt.Sprintf("order-%d", order), func(t *testing.T) {
							t.Parallel()
							policies := slices.Clone(group.Policies)
							for i := range policies {
								policies[i].Rules = slices.Clone(policies[i].Rules)
								if order&1 != 0 {
									slices.Reverse(policies[i].Rules)
								}
							}
							if order&2 != 0 {
								slices.Reverse(policies)
							}
							program, err := Compile(policies)
							if err != nil {
								t.Fatalf("compile fixture: %v", err)
							}
							got, err := program.Evaluate(*c.Facts)
							if (err != nil) != *c.Want.EvaluationError {
								t.Fatalf("evaluation error = %v, want error=%v", err, *c.Want.EvaluationError)
							}
							if !reflect.DeepEqual(normalizeEnterpriseDecision(got), normalizeEnterpriseDecision(c.decision)) {
								t.Fatalf("decision = %+v, want %+v", got, c.decision)
							}
						})
					}
				})
			}
		}
	}
}

func TestEnterpriseCorpusRejectsIncompleteExpectations(t *testing.T) {
	data, err := os.ReadFile("testdata/enterprise-conformance/predicates.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEnterpriseCorpus(data); err != nil {
		t.Fatalf("valid control: %v", err)
	}
	for name, bad := range map[string][]byte{
		"malformed":        []byte(`{`),
		"trailing":         append(slices.Clone(data), []byte(` {}`)...),
		"trailing-invalid": append(slices.Clone(data), []byte(` {`)...),
		"unknown-version":  bytes.Replace(data, []byte(`"version": 1`), []byte(`"version": 2`), 1),
		"unknown-field":    bytes.Replace(data, []byte(`"groups":`), []byte(`"unexpected": true, "groups":`), 1),
		"unknown-fact":     bytes.Replace(data, []byte(`"facts": {`), []byte(`"facts": {"Unexpected": true,`), 1),
		"unknown-decision": bytes.Replace(data, []byte(`"decision": {`), []byte(`"decision": {"Unexpected": true,`), 1),
		"missing-facts":    bytes.Replace(data, []byte(`"facts": {"ActorPath": "/usr/bin/sh"}`), []byte(`"facts": null`), 1),
		"missing-error":    bytes.Replace(data, []byte(`"evaluationError": false`), []byte(`"evaluationError": null`), 1),
		"missing-block":    bytes.Replace(data, []byte(`"Block": true,`), nil, 1),
		"null-block":       bytes.Replace(data, []byte(`"Block": true`), []byte(`"Block": null`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(data, bad) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := decodeEnterpriseCorpus(bad); err == nil {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
	for _, name := range []string{"duplicate-group", "duplicate-case"} {
		t.Run(name, func(t *testing.T) {
			corpus, err := decodeEnterpriseCorpus(data)
			if err != nil {
				t.Fatal(err)
			}
			if name == "duplicate-group" {
				corpus.Groups = append(corpus.Groups, corpus.Groups[0])
			} else {
				group := &corpus.Groups[0]
				group.Cases = append(group.Cases, group.Cases[0])
			}
			bad, err := json.Marshal(corpus)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeEnterpriseCorpus(bad); err == nil {
				t.Fatal("duplicate fixture identifier accepted")
			}
		})
	}
	for i := range reflect.TypeFor[Decision]().NumField() {
		field := reflect.TypeFor[Decision]().Field(i).Name
		t.Run("missing-"+field, func(t *testing.T) {
			corpus, err := decodeEnterpriseCorpus(data)
			if err != nil {
				t.Fatal(err)
			}
			c := &corpus.Groups[0].Cases[0]
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(c.Want.Decision, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, field)
			c.Want.Decision, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := json.Marshal(corpus)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeEnterpriseCorpus(bad); err == nil {
				t.Fatal("incomplete expected decision accepted")
			}
		})
	}
}
