// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

const (
	workerScope          = "fresh-scope-objects-union-stage-v1"
	workerModel          = "ig-owned-logical-v1"
	workerRuntimePackage = gadgetModule + "/gadgets/enforce_exec/fullruntime"
	workerCarrierTarget  = workerRuntimePackage + ".sharedWorkerEvidence"
)

type workerSnapshot struct {
	RawProfile map[string]string `json:"raw_profile"`
	Consumer   consumerSnapshot  `json:"consumer"`
	Inputs     map[string]string `json:"build_and_proof_inputs"`
	Packages   []string          `json:"selected_import_closure"`
}
type workerCheck struct {
	Package      string `json:"package"`
	Test         string `json:"test"`
	EventsSHA256 string `json:"events_sha256"`
}
type workerTerm struct {
	Name           string `json:"name"`
	Source         string `json:"source"`
	SourceSHA256   string `json:"source_sha256"`
	Symbol         string `json:"symbol"`
	Formula        string `json:"formula"`
	Bytes          uint64 `json:"bytes"`
	Lifetime       string `json:"lifetime"`
	Check          string `json:"check"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}
type workerTail struct {
	Terms     []workerTerm `json:"terms"`
	Bootstrap uint64       `json:"bootstrap_bytes"`
	Tail      uint64       `json:"tail_bytes"`
}
type workerPrebuildV1 struct {
	SchemaVersion    int            `json:"schema_version"`
	Phase            string         `json:"phase"`
	EvidenceScope    string         `json:"evidence_scope"`
	AccountingDomain string         `json:"accounting_domain"`
	ModelRevision    string         `json:"model_revision"`
	NativeActivation string         `json:"native_activation"`
	Snapshot         workerSnapshot `json:"snapshot"`
	InputsSHA256     string         `json:"inputs_sha256"`
	ProfileSHA256    string         `json:"profile_sha256"`
	Checks           []workerCheck  `json:"checks"`
	ChecksSHA256     string         `json:"checks_sha256"`
	TailProof        workerTail     `json:"tail_proof"`
	TailProofSHA256  string         `json:"tail_proof_sha256"`
	BootstrapBytes   uint64         `json:"bootstrap_bytes"`
	TailBytes        uint64         `json:"tail_bytes"`
	Runner           runnerIdentity `json:"runner"`
}
type workerBuildV1 struct {
	SchemaVersion    int            `json:"schema_version"`
	Phase            string         `json:"phase"`
	EvidenceScope    string         `json:"evidence_scope"`
	NativeActivation string         `json:"native_activation"`
	PrebuildSHA256   string         `json:"prebuild_sha256"`
	Carrier          string         `json:"carrier"`
	Snapshot         workerSnapshot `json:"snapshot"`
	Binary           binaryEvidence `json:"binary"`
	Runner           runnerIdentity `json:"runner"`
}

func workerJSONHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return hashBytes(b)
}

func workerDigest(s string) bool {
	return validHash(s) && s == strings.ToLower(s) && s != strings.Repeat("0", 64)
}

func decodeWorkerPrebuild(data []byte) (workerPrebuildV1, error) {
	var r workerPrebuildV1
	if err := checkUniqueJSON(data); err != nil {
		return r, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	var raw, shape any
	if err = json.Unmarshal(data, &raw); err != nil {
		return r, err
	}
	if err = json.Unmarshal(canonical, &shape); err != nil {
		return r, err
	}
	if !reflect.DeepEqual(raw, shape) {
		return r, errors.New("worker record requires exact canonical field schema")
	}
	return r, validateWorkerPrebuild(r)
}

func validateWorkerPrebuild(r workerPrebuildV1) error {
	if r.SchemaVersion != 1 || r.Phase != "PREBUILD" || r.EvidenceScope != workerScope || r.AccountingDomain != workerModel || r.ModelRevision != "worker-model-v1" || r.NativeActivation != "NOT_QUALIFIED" {
		return errors.New("incompatible worker scope/schema")
	}
	if r.InputsSHA256 != workerJSONHash(r.Snapshot.Inputs) || r.ProfileSHA256 != workerProfileHash(r.Snapshot) || r.ChecksSHA256 != workerJSONHash(r.Checks) || r.TailProofSHA256 != workerJSONHash(r.TailProof) {
		return errors.New("worker evidence digest mismatch")
	}
	if err := validateWorkerChecks(r.Checks); err != nil {
		return err
	}
	proof, err := deriveWorkerTail(r.Snapshot) //nolint:staticcheck // SA4023: stub refuses by design.
	if err != nil {                            //nolint:staticcheck // SA4023: deriveWorkerTail refuses until its dependency lands; keep guard.
		return err
	}
	if !reflect.DeepEqual(proof, r.TailProof) || r.BootstrapBytes != proof.Bootstrap || r.TailBytes != proof.Tail || proof.Bootstrap == 0 || proof.Tail == 0 || proof.Tail > ^uint64(0)-proof.Bootstrap {
		return errors.New("worker proof not generated from fixed source-bound specification")
	}
	if !workerDigest(r.Runner.SHA256) || r.Runner.BuildInfo == nil || r.Runner.SourceLinkage != "UNPROVEN" {
		return errors.New("missing worker runner identity")
	}
	return nil
}

func workerCarrier(r workerPrebuildV1, recordHash string) (string, error) {
	if err := validateWorkerPrebuild(r); err != nil {
		return "", err
	}
	if !workerDigest(recordHash) {
		return "", errors.New("invalid exact PREBUILD digest")
	}
	profile := "01"
	if r.Snapshot.Consumer.Profile["GOEXPERIMENT"] == "greenteagc" {
		profile = "02"
	}
	return fmt.Sprintf("IGW100010001%s%s%s%s%s%s%016x%016x", profile, recordHash, r.InputsSHA256, r.ProfileSHA256, r.ChecksSHA256, r.TailProofSHA256, r.BootstrapBytes, r.TailBytes), nil
}

func workerProfileHash(s workerSnapshot) string {
	return workerJSONHash(struct {
		Raw       map[string]string
		Effective map[string]string
	}{s.RawProfile, s.Consumer.Profile})
}
