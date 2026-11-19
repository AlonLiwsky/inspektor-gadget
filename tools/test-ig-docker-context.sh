#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0

# Exercise Docker's ignore rules without pulling an image or executing a binary.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/context/gadgets/enforce_exec" "$tmp/output"
cp "$root/Dockerfiles/ig.Dockerfile.dockerignore" "$tmp/context/.dockerignore"
printf 'FROM scratch\nCOPY . /\n' > "$tmp/context/Dockerfile"

for package in policy runtime fullpolicy; do
    cp -R "$root/gadgets/enforce_exec/$package" "$tmp/context/gadgets/enforce_exec/"
done

# These inputs must not enter the context when allowing the Go packages.
excluded=(
    .git/context-sentinel
    .omx/context-sentinel
    .env
    gadgets/trace_exec/program.bpf.c
    gadgets/enforce_exec/full/program.bpf.c
    gadgets/enforce_exec/test/abi3-gatea/context-sentinel
    gadgets/enforce_exec/runtime/generated.o
    gadgets/enforce_exec/runtime/credentials.env
)
for path in "${excluded[@]}"; do
    mkdir -p "$tmp/context/$(dirname "$path")"
    printf 'must stay excluded\n' > "$tmp/context/$path"
done

docker buildx build --progress=plain --output "type=local,dest=$tmp/output" "$tmp/context"

for package in policy runtime fullpolicy; do
    for source in "$root/gadgets/enforce_exec/$package/"*.go; do
        path="${source#"$root/"}"
        if [[ "$source" == *_test.go ]]; then
            test ! -e "$tmp/output/$path"
        else
            cmp "$source" "$tmp/output/$path"
        fi
    done
done
for path in "${excluded[@]}"; do
    test ! -e "$tmp/output/$path"
done
echo "ig Docker context includes enforcement Go sources and excludes unrelated inputs"
