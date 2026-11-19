// Copyright 2019-2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ig

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sync"
)

// Piped logrus output uses a complete text-format line, with an optional
// timestamp. Its bare running... message is normally unquoted. Never accept
// the node-prefixed remote marker or a substring of a different log message.
var localRunning = regexp.MustCompile(`^(?:time="[^"]*" )?level=debug msg=(?:running\.\.\.|"running\.\.\.")$`)

// Startup markers are short; discard longer diagnostic lines without retaining
// their tail, which could otherwise be mistaken for a fresh marker.
const maxLocalReadinessLine = 4096

type localReadiness struct {
	mu         sync.Mutex
	pending    []byte
	discarding bool
	ready      chan struct{}
}

func newLocalReadiness() *localReadiness {
	return &localReadiness{ready: make(chan struct{}), pending: make([]byte, 0, maxLocalReadinessLine)}
}

func (r *localReadiness) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	select {
	case <-r.ready:
		return n, nil
	default:
	}
	for len(p) > 0 {
		newline := bytes.IndexByte(p, '\n')
		end := newline
		if end < 0 {
			end = len(p)
		}
		if !r.discarding {
			if end > maxLocalReadinessLine-len(r.pending) {
				r.pending = r.pending[:0]
				r.discarding = true
			} else {
				r.pending = append(r.pending, p[:end]...)
			}
		}
		if newline < 0 {
			return n, nil
		}
		matched := !r.discarding && localRunning.Match(r.pending)
		r.pending = r.pending[:0]
		r.discarding = false
		if matched {
			r.pending = nil
			close(r.ready)
			return n, nil
		}
		p = p[newline+1:]
	}
	return n, nil
}

func (r *localReadiness) wait(ctx context.Context, exited <-chan struct{}, exitError func() error) error {
	failure := func(err error) error { return fmt.Errorf("local gadget readiness: %w", err) }
	exitFailure := func() error {
		err := exitError()
		if err == nil {
			err = fmt.Errorf("command exited before capture")
		}
		return failure(err)
	}
	select {
	case <-ctx.Done():
		return failure(ctx.Err())
	case <-exited:
		return exitFailure()
	case <-r.ready:
		if err := ctx.Err(); err != nil {
			return failure(err)
		}
		select {
		case <-exited:
			return exitFailure()
		default:
			return nil
		}
	}
}
