// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

var resolverKeys = []string{"GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOPROXY", "GOPRIVATE", "GOMODCACHE"}

// These digests compare exact settings without publishing credential-bearing
// URLs, paths or queries. They are not authentication or secret-strength proof.
func publishResolverHashes(profile map[string]string) map[string]string {
	hashes := make(map[string]string, len(resolverKeys))
	for _, key := range resolverKeys {
		hashes[key] = hashBytes([]byte(profile[key]))
		delete(profile, key)
	}
	return hashes
}

// Never echo arbitrary subprocess text: credentials can occur anywhere, not
// just URL userinfo. Static categories retain actionable, bounded diagnostics.
func safeGoDiagnostic(data []byte) string {
	if len(data) > 8192 {
		data = data[:8192]
	}
	text := strings.ToLower(string(data))
	for _, category := range []struct {
		needles []string
		message string
	}{
		{[]string{"401", "403", "authentication", "terminal prompts disabled"}, "module authentication/authorization failed"},
		{[]string{"directory not found", "no such file or directory"}, "selected path is unavailable"},
		{[]string{"missing go.sum entry", "updates to go.mod needed"}, "module manifests need preparation before readonly qualification"},
		{[]string{"cannot find module providing package", "no required module provides package"}, "required package is unavailable in the consumer graph"},
		{[]string{"unknown revision", "invalid version"}, "requested module version is unavailable"},
		{[]string{"checksum mismatch"}, "module checksum validation failed"},
		{[]string{"syntax error"}, "Go source contains a syntax error"},
		{[]string{"undefined:"}, "Go source references an undefined identifier"},
	} {
		for _, needle := range category.needles {
			if strings.Contains(text, needle) {
				return category.message
			}
		}
	}
	return "unclassified subprocess details withheld to protect resolver credentials"
}

func goCommandError(operation string, err error, stderr []byte) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("go %s failed (exit %d): %s", operation, exit.ExitCode(), safeGoDiagnostic(stderr))
	}
	return fmt.Errorf("go %s could not start; subprocess details withheld", operation)
}

// Captures only a bounded diagnostic prefix; the full stream is never logged.
type goDiagnosticBuffer struct{ bytes []byte }

func (b *goDiagnosticBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 8192 - len(b.bytes)
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.bytes = append(b.bytes, p...)
	return n, nil
}

func runModelTests(command *exec.Cmd, output, logs io.Writer) error {
	var events bytes.Buffer
	var diagnostic goDiagnosticBuffer
	command.Stdout = &events
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		return goCommandError("test", err, diagnostic.bytes)
	}
	if err := checkTestEvents(bytes.NewReader(events.Bytes()), nil); err != nil {
		return errors.New("qualification test events invalid, missing or skipped; raw child output withheld")
	}
	// Only publish already-validated action/package/test identifiers. Output text
	// is not needed by the oracle and can contain secrets from child diagnostics.
	decoder := json.NewDecoder(bytes.NewReader(events.Bytes()))
	encoder := json.NewEncoder(output)
	for {
		var event testEvent
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	if len(diagnostic.bytes) != 0 {
		_, err := fmt.Fprintln(logs, "go test diagnostic:", safeGoDiagnostic(diagnostic.bytes))
		return err
	}
	return nil
}
