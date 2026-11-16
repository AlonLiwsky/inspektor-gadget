#!/usr/bin/env bash
# Adapted from ig15-build-only-20261028/tooling/run-build.sh: NO runtime/load.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd -- "$here/../../../../.." && pwd)
out="$here/build-output";mkdir -p "$out"
image=$(docker image inspect ig15-local-build-only:clang21.1.8 --format '{{.Id}}')
docker image inspect "$image" > "$out/builder-image.json"
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=4g --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,size=256m --mount type=bind,src="$repo",dst=/src,readonly --mount type=bind,src=/home/mbertschy/ig15-kernel-reconstruction-20261028/matched,dst=/btf,readonly --mount type=bind,src="$out",dst=/out "$image" bash /src/gadgets/enforce_exec/test/abi3-gatea/nesting/build.sh /out 2>&1 | tee "$out/build.log"
