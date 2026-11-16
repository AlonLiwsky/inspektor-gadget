// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

// deriveWorkerConditionalComposition combines the reviewed numerical components
// and binds their terms to exact validated generated-check identities. It does
// NOT authenticate supplied digests or settle approved-consumer opaque-input,
// release-provenance or sentinel assumptions. Only the controlled producer can
// generate the artifacts; complete deriveWorkerTail deliberately still refuses.
//
// Compiler object/union debit is cumulative and outside fixed B/T. The separately
// owned startup carrier575 and assertion-site24 are not added here and are not
// a complete startup bound. Concrete warmed library-cache owners stay separate.
func deriveWorkerConditionalComposition(s workerSnapshot, checks []workerCheck) (workerTail, error) {
	var result workerTail
	if err := validateWorkerChecks(checks); err != nil {
		return result, err
	}
	project, err := deriveWorkerProject(s)
	if err != nil {
		return result, err
	}
	dependency, err := deriveWorkerDependency(s)
	if err != nil {
		return result, err
	}
	tail, err := workerProofSum(project.ProjectTail, dependency.Tail)
	if err != nil {
		return result, err
	}
	// Check the complete fixed reservation as well as the two tail components.
	if _, err := workerProofSum(project.Bootstrap, tail); err != nil {
		return result, err
	}
	artifacts := make(map[string]string, len(checks))
	for _, check := range checks {
		artifacts[check.Package+"/"+check.Test] = check.EventsSHA256
	}
	terms := []workerTerm{
		{
			Name: "bootstrap", Source: "fullruntime/shared_operation_context.go",
			Symbol: "sharedOperationContext", Formula: "136+16+3*112+3*16",
			Bytes: project.Bootstrap, Lifetime: "whole-operation-bootstrap",
			Check: workerRuntimePackage + "/" + workerRuntimeProofCheckName,
		},
		{
			Name: "project-tail", Source: "fullruntime/proc_pin.go",
			Symbol:  "readPinnedInitStart;checkBindingScope;prepareSharedWorkerLocked",
			Formula: "max(4*65536+1048592+48+16,80+16,16+(32+1112+48+3+56+112+16)+1112)",
			Bytes:   project.ProjectTail, Lifetime: "maximum-project-phase-within-operation",
			Check: workerRuntimePackage + "/" + workerRuntimeProofCheckName,
		},
		{
			Name: "dependency-tail", Source: "closure/github.com/cilium/ebpf/map.go",
			Symbol:  "Map.update;Map.lookup;Program.Run",
			Formula: "max(1152+4+8+4*8+2*32+70+78+20+26,4+8+5*8+2*32+70+78+20+26,max(164,207,160,170))",
			Bytes:   dependency.Tail, Lifetime: "maximum-joined-command-cohort;no-retention-across-cleanup",
			Check: workerRuntimePackage + "/" + workerDependencyProofCheckName,
		},
		{
			Name: "dependency-stdlib-premise", Source: "toolchain/src/encoding/binary/binary.go",
			Symbol: "Append;Errno.Error;FormatInt", Formula: "included-in-dependency-tail;no-additional-owner",
			Lifetime: "dependency-command-phase-premise",
			Check:    workerRuntimePackage + "/" + workerDependencyStdlibProofCheckName,
		},
		{
			Name: "compiler-debit-premise", Source: "fullpolicy/workspace_limited.go",
			Symbol: "CompileSharedPolicyLimited;NewSharedSnapshotLimited", Formula: "sum(D_i)+D_union-charged-separately;zero-added-to-fixed-B/T",
			Lifetime: "cumulative-debit-outside-fixed-B/T",
			Check:    testedPackage + "/" + workerCompilerProofCheckName,
		},
	}
	for i := range terms {
		// Source hashes identify the reviewed source; artifact hashes identify
		// generated compiler output. They are intentionally different inputs.
		terms[i].SourceSHA256 = s.Inputs[terms[i].Source]
		terms[i].ArtifactSHA256 = artifacts[terms[i].Check]
	}
	return workerTail{Terms: terms, Bootstrap: project.Bootstrap, Tail: tail}, nil
}
