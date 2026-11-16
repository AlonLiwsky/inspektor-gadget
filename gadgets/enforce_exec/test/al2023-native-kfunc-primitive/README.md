# AL2023 sleepable native argv kfunc — isolated feasibility fixture

Default-off observer only. No product image, policy verdict, admission or Ready
claim is added. Do not load the module or attach the BPF program before an
independent review and an explicitly isolated exact-kernel run.

## Plan and invariant

1. Recover exact vendor kernel-devel/config/symbol versions for
   `6.12.113-138.209.amzn2023.x86_64` and
   `6.18.56-125.164.amzn2023.x86_64`; never substitute host headers.
2. Register one module-owned, LSM-only `KF_SLEEPABLE` kfunc. Read the current
   trusted `linux_binprm` pending mm synchronously, with at most 64 arguments
   and 4096 canonical bytes. No native task registry or retained references.
3. Call only from `lsm.s/bprm_check_security`, without a BPF lock/RCU section
   across the call. The observer always returns the incoming LSM result,
   including on acquisition errors; it grants no role or enforcement decision.
4. Host-build module and BPF object, test framing/limit failures, independently
   review, then let the parent run the exact-kernel load/attach matrix.

Kfunc ABI is version-specific. The output is scalar-only and must be fully
initialized before exposure; errors clear completeness and cannot become prefix
matches. Byte bounds do not prove a latency bound: GUP may sleep. This experiment
must not be promoted to the strict Audit product contract without that review.

## Required live proof (not yet performed)

Both exact vendor kernels: module BTF/registration and trusted bprm/output-buffer
verifier acceptance; ordinary and same-bprm interpreter phases; 64 args/4096
bytes, empty/non-ASCII/page-crossing/env separation; 65/4097 rejection; read
faults and prior-LSM errno preservation; normal detach/module unload with no
warnings or retained references. Also test the real opaque WORK/tail-call image
before claiming integration. Default-AMI module-signature/lockdown acceptance is
a separate gate; no signature bypass, forced unload or kernel replacement.

References: https://docs.kernel.org/bpf/kfuncs.html and exact vendor headers.
G021's pending-mm copy algorithm is a reference only; its async worker, lifetime
record cap and Audit operational-EPERM behavior are deliberately not reused.

## Host qualification and reproduction

Vendor inputs were downloaded from the versioned AL2023 repositories for
`2023.12.20261026` and `2023.12.20261102`, not inferred from a stock kernel.
The exact extracted `kernel-devel` packages (SHA256) are:

- `kernel6.12-devel-6.12.113-138.209.amzn2023.x86_64.rpm`:
  `0d7867f7f75b2f4a96543ef0b9f7c45eade5781ea349a65483e07f5eff546495`
- `kernel6.18-devel-6.18.56-125.164.amzn2023.x86_64.rpm`:
  `01c2a7240e1d4092a93a4f89de43239a4fadec241e1045c980519daa1b65bbb8`

AWS download URLs use `https://cdn.amazonlinux.com/al2023/blobstore/<sha>/<filename>`.
The ignored `.build/` directory retains the packages, extracted vendor inputs,
versioned primary repository metadata, build logs, and objects. These are local
artifacts, not committed or portable proof of a live run.

The exact devel headers/config/Module.symvers plus captured exact running BTF
were used for both builds. The build host uses GCC 14.2 instead of vendor GCC
11.5; the warning remains visible. A host `resolve_btfids` tool supplies the
utility absent from the vendor devel RPM. Both resulting modules have BTF and
versioned symbols; this is **compile proof only**, not verifier/load proof.

Build from this directory, using an isolated extracted vendor tree whose
`vmlinux` is a symlink to the corresponding exact captured BTF:

```sh
./build-module.sh "$KERNEL_DIR" "$EXACT_BTF" "$RESOLVE_BTFIDS" "$OUT"
gcc -std=c11 -Wall -Wextra -Werror -O2 framing_test.c -o .build/framing-test
.build/framing-test
bpftool btf dump file "$EXACT_BTF" format c > .build/vmlinux.h
clang-21 -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror \
  -I .build -I . -I /usr/include -c observer.bpf.c -o .build/observer.bpf.o
# From repository root:
go build ./gadgets/enforce_exec/test/al2023-native-kfunc-primitive/runner
go vet ./gadgets/enforce_exec/test/al2023-native-kfunc-primitive/runner
```

The build helper refuses unknown releases or incorrect BTF. It has no load or
install path. The runner requires the exact release, vmlinuz digest, running BTF
digest, already-loaded module BTF, an empty explicitly named isolated cgroup2,
and the expected sleepable program/map ABI. It never loads/unloads a module.
No run is authorized by these commands; independent review precedes attachment.

The eight baseline cases are `short`, `args64`,
`bytes4096`, `args65`, `bytes4097`, `empty`, `nonascii`, and `environment`.
Each spawns one controlled ELF process directly into the cgroup, requires exactly
one observation and exact canonical bytes/offsets (or explicit oversized output),
and verifies successful process completion. Injected acquisition faults,
preexisting LSM-denial preservation and default AMI signing remain separate
qualification gates. No fixture result proves end-to-end product readiness.

### Phase and page-crossing cases: host-compiled WIP

The new `shebang` and `pagecross` cases are **not live-qualified**. Host compilation
and runner unit tests do not establish verifier acceptance or runtime correctness.
Earlier live eight-case results apply only to the older observer/runner pair:

- Observer SHA256: `365593deded75a39bd7bfc8a0f914e24fc12e847044a49fbb45291e58a83aa87`
- Runner SHA256: `a24c82722aa1fee9295cd9afe6d859d10b886c9014d435d5058217fdc2c190b9`

Rebuild the current observer and runner together. The current sample ABI is
4424 bytes; the runner rejects the older 4400-byte observer. Keep new artifacts
under distinct names, such as `.build/phase-observer.bpf.o` and
`.build/phase-runner`, rather than overwriting the older evidence pair. Use the
observer build command above with that new output filename.

From this fixture directory, build the controlled ELF interpreter and runner:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O2 phase_helper.c -o .build/phase-helper
go build -o .build/phase-runner ./runner
go test ./runner
go vet ./runner
```

Build the helper on the isolated target or with a compatible userspace toolchain.
`shebang` requires this helper, not `/bin/true`: the runner creates a temporary
script, checks both exact argv phases under the same task and `bprm`, and requires
the helper's success marker. The helper path must be absolute, whitespace-free
and short enough for the runner's shebang-length check. `pagecross` uses a
4096-byte argv vector and checks that the observed argument actually crosses a
4 KiB page boundary; length alone is not accepted as proof.

The following privileged invocations document the intended interface only;
they have **not been executed or live-qualified**. They require independent
review, the exact-kernel prerequisites above, an already-loaded reviewed module,
the newly rebuilt observer, and an existing empty isolated cgroup:

```sh
ISOLATED_CGROUP=/sys/fs/cgroup/ig15-g020-kfunc-phase
sudo "$PWD/.build/phase-runner" -object "$PWD/.build/phase-observer.bpf.o" \
  -cgroup "$ISOLATED_CGROUP" -exe "$PWD/.build/phase-helper" -case shebang
sudo "$PWD/.build/phase-runner" -object "$PWD/.build/phase-observer.bpf.o" \
  -cgroup "$ISOLATED_CGROUP" -exe /bin/true -case pagecross
```

### Modern resolver / vendor Kbuild compatibility

The host resolver emits sidecar blobs, whereas these vendor Kbuild versions
expect in-place ID resolution. Earlier compile-only objects therefore had an
empty embedded registration set despite populated sidecars; those artifacts
must not be used as registration evidence.

`build-module.sh` now regenerates `.BTF`, distilled `.BTF.base`, and `.BTF_ids`
together with `--fatal_warnings --distill_base`, embeds BTF and base with
`objcopy`, and patches the IDs with `--patch_btfids`. It then runs
`check-module.py` against the **embedded** sections. That check parses split BTF
with its embedded base and requires exactly one nonzero function ID matching
`ig_capture_pending_argv`, set8 flags `1`, and kfunc flags `0x30` (sleepable and
trusted arguments). Missing, empty, mismatched or extra registration entries
fail the build. This structural check is still not live load/verifier proof.

Run offline structural regression tests with:

```sh
python3 test_module_structure.py
python3 check-module.py .build/module-6.12/ig_argv_kfunc.ko
python3 check-module.py .build/module-6.18-vendor-toolchain/ig_argv_kfunc.ko
```

### Canonical trusted argument preflight / vendor-toolchain experiment

Registration alone is insufficient. `check-module.py` also follows the kfunc's
prototype and first pointer argument and requires that its pointee ID be the
`linux_binprm` entry in the **embedded distilled base**. A separate module-local
struct with the same name/layout is rejected, not treated as equivalent. The
base is generated against the exact hash-checked vendor BTF by the build helper;
its identity is relocated by the kernel on load. Live verifier acceptance still
requires a real run.

The previous host-toolchain 6.18 object fails this stricter preflight. One bounded
offline rebuild using official AL2023 GCC 11.5 and pahole 1.29 passes: arg0 now
points to distilled base ID 4 (`linux_binprm`), not a duplicate split-module type.
This experiment changed neither the kfunc ABI nor its trust/sleepable flags.
The old 6.12 object also passes the stricter check.

Exact RPM inputs, checked against the versioned repository's SHA256 metadata:

- gcc 11.5.0-5.amzn2023.0.5: `417e5f14d74b47832303734e61657e8c6e1ca9ac2f763cf6e3f2e69fed3e31a2`
- cpp 11.5.0-5.amzn2023.0.5: `f3d30581358013d2c4b38e3847c5771cf6ed75ffa2b0a820c1102cb4f4e33d10`
- dwarves 1.29-1.amzn2023.0.2: `b778d0ec41683cd565eea7f587df757c7354842b342cedf487daec05380ec28e`
- libdwarves1 1.29-1.amzn2023.0.2: `0e9cb68360aae1cbf9e4d97d9b4594a07ad17fa965aa4b3770aa2a97957bbeb0`
- isl 0.16.1-13.amzn2023.0.3: `c70a7f5b406a3219d45d03b0057edf6e2634df4f25ea596a9f3a2f98803c4baa`

Local evidence: `.build/vendor-tools-fetch.log` and
`.build/module-6.18-vendor-toolchain/{build.log,base.raw,combined.raw}`.
The module SHA256 is
`89ae0ebe219c5ae62dff95d2ea818b753bd246f837799d91a9c2e8f8cf635d03`;
its ELF compiler comments identify GCC 11.5.0 (Red Hat 11.5.0-5).
Tool binaries/libraries were extracted under `.build/vendor-tools/root`, not
installed system-wide. This matches compiler/pahole versions, not the entire
vendor build environment: host assembler/linker and modern resolver remain.

Reproduction with those extracted packages:

```sh
T="$PWD/.build/vendor-tools/root"
LD_LIBRARY_PATH="$T/usr/lib64" \
MAKEFLAGS="CC=$T/usr/bin/gcc PAHOLE=$T/usr/bin/pahole" \
  ./build-module.sh "$KERNEL_DIR" "$EXACT_BTF" "$RESOLVE_BTFIDS" \
  "$PWD/.build/module-6.18-vendor-toolchain"
```

No VM/module load was performed as part of this offline experiment.
