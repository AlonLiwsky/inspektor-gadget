# Local syntax-model corroboration

This opt-in development command checks the **local** Go1.27.3 linux/amd64 model.
It is not production artifact attestation, a runtime gate, or complete compiler
memory admission. Generic compiler tests and supported toolchains are unchanged.

From the repository root, supply the exact noninstrumented profile explicitly:

```sh
env GOENV=off GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
  GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
  GOEXPERIMENT= GODEBUG= GOCOMPILEDEBUG= \
  /absolute/go1.27.3/bin/go run ./gadgets/enforce_exec/fullpolicy/qualification \
  -go /absolute/go1.27.3/bin/go \
  >qualification-events.jsonl 2>qualification-report.json
```

For this exact pinned version, `GOEXPERIMENT=greenteagc` is also accepted:
GreenTeaGC is already enabled by default. These two raw values select the same
effective experiments, but remain distinct in raw build metadata. The runner
preserves the actual `GOEXPERIMENT` value in `effective_profile`; it does not
normalize settings or claim byte-identical artifacts. `none`, `nogreenteagc`,
compound values, whitespace variants and every other experiment are rejected.
The numerical model/revision is unchanged.

Unsupported supplied settings are rejected, not silently converted into a
successful profile. No extra Go test/build flags are accepted. The selected Go
executable must match the effective GOROOT; the identity test's PATH resolves
`go` to that same directory. Persistent GOENV settings and automatic toolchain
switching are disabled. `go env` reports disabled GOENV as an empty file path.

`sources.json` pins eleven audited model files plus four profile-control files from the official immutable Go commit
`2aae1000ea1d4b28923b96db28acf4e3b99d6aff`, obtained at:
`https://raw.githubusercontent.com/golang/go/<commit>/src/<manifest-path>`.
Expected hashes are **not** generated from the local GOROOT being checked.
The additional controls are `internal/buildcfg/{exp,cfg}.go`,
`cmd/go/internal/cfg/cfg.go` and `internal/goexperiment/exp_greenteagc_on.go`: they
establish the default-on flag, effective tool tags and separate raw setting.
This source evidence does not authenticate the installed compiler binary or its
embedded defaults; the existing local-only/artifact-linkage limitations apply.

The runner verifies all source hashes, runs the fixed fifteen model tests without
race/coverage/sanitizer/overlay flags or caching (`-count=1`), and requires every
named test to run and pass. Any skipped, missing, failed or malformed event, or
nonzero process exit, fails corroboration. Sources, selected executable and model
worktree inputs are checked again after the test. Successful JSON records the
selected executable/hash, effective settings, source pins, current input hashes
and observed tests, with production artifact linkage explicitly **ABSENT**.

Exit0 means only these local checks succeeded. It does not prove the local Go
binary was built from the matching source tree, link this run to a production
image, cover other toolchains, or establish full `CompileBytes` accounting.

## Phase 1: consumer source evidence and binary binding

This command can also inspect a **consumer-selected, versioned dependency** and
bind that evidence to final executable bytes. Every successful phase-1 record
has `schema_version: 1`, `evidence_scope: "syntax-model"`,
`native_budget_qualified: false`, and `complete_model_revision: null`.
**Neither phase authorizes native policy activation or full compiler admission.**

Use the exact environment above for both invocations. Supply a *new* report path;
reports are exclusive-create JSON files, separate from stdout test events and
stderr diagnostics. No arbitrary Go flags are accepted.

```sh
qualification -go /absolute/go1.27.3/bin/go \
  -consumer /absolute/node-agent -consumer-command ./cmd \
  -report /evidence/PREBUILD.json > /evidence/tests.jsonl

# A future trusted producer must build EXACTLY the recorded package target,
# using the recorded toolchain/profile and supported production flags.
qualification -go /absolute/go1.27.3/bin/go \
  -consumer /absolute/node-agent -consumer-command ./cmd \
  -check-report /evidence/PREBUILD.json -bind-binary /output/node-agent \
  -report /evidence/BUILD.json
```

The command target must be one module-relative, module-associated **main package**
(such as `./cmd`). Direct file builds (`./cmd/main.go`) are rejected: Go gives them
`command-line-arguments` and an empty main module, so their identity cannot be
bound strictly. Current producers still need a separately reviewed package-target
migration and published dependency pins; this change does not modify those jobs.

### What is checked

- Go-list resolution and the fixed fifteen tests run from the **consumer root**,
  under its module graph, not by switching into the dependency's checkout.
- Remote versioned replacements (including the Kubescape fork) are allowed and
  original/effective module identities recorded. Local, main-module and
  versionless fullpolicy substitutes are refused. Effective replacement sums are
  compared; Go correctly omits the original sum for replaced modules. The selected
  MVS inventory rejects local/versionless dependencies. Unlinked selected modules
  may lack an as-yet-unfetched sum; every linked module requires its effective sum.
- Before/after snapshots record consumer `go.mod`/`go.sum`, module-graph hash,
  selected fullpolicy/model/qualification source tree, selected module manifest,
  declared command's selected files/embeds, executable/compiler/assembler/linker
  hashes, pinned GOROOT source hashes, and effective/raw model profile. Exact
  resolver settings have SHA256 equality commitments, never raw credential URLs.
  Missing selected qualification sources are refused.
- All fifteen tests must run and pass without skips or malformed output. PREBUILD
  has `phase: "PREBUILD"` and `artifact_linkage: "ABSENT"`.
- Binding requires the unchanged complete PREBUILD snapshot, exact main module
  and package metadata, and matching metadata for **every linked dependency**
  against the selected MVS identities, including effective replacements/sums.
  Selected but unlinked modules need not appear in the binary. Linked dependencies
  are a **subset** of the consumer graph, not an assertion that every graph
  module is linked. BuildInfo is module-level metadata; it does not prove that a
  particular fullpolicy function or package was retained by the linker.
- BuildInfo and SHA256 use the **same captured executable bytes**. File identity,
  size, modification time and path hash are rechecked, as is the exact prior
  report hash. A successful BUILD records raw actual build settings separately
  from test settings and `artifact_linkage: "LINKED_BINARY_ONLY"`.
- Duplicate JSON keys, unknown schema fields, missing markers, duplicate binary
  module/settings entries, changed inputs and unsupported profiles are refused.

### Binary setting policy (schema 1)

| Setting | Rule |
| --- | --- |
| GoVersion | Exactly `go1.27.3` |
| GOOS / GOARCH / GOAMD64 | Present: `linux` / `amd64` / `v1` |
| CGO_ENABLED / -buildmode / -compiler | Present: `0` / `exe` / `gc` |
| GOEXPERIMENT | Absent means empty; otherwise exact raw `greenteagc`; must match PREBUILD |
| GOFIPS140 | Absent means off; non-off refused |
| DefaultGODEBUG | Absent means empty; exact match to Go-list selected main metadata |
| -ldflags | Absent means none; only `-s`, `-w`, and separate `-X` assignments to `github.com/armosec/private-node-agent/pkg/version.{Version,Commit,BuildTime}` |
| VCS metadata | Recorded as observed; not a signature or trust assertion |
| -trimpath | Refused: Go deliberately hides linker flags when enabled |
| -pgo / implicit default.pgo | Refused; selected main and model-test directories must have no `default.pgo` |
| race / sanitizers / coverage / gcflags / asmflags / tags / unknown recorded settings | Refused when present |
| Build-only overlay | Not recorded by BuildInfo; absence cannot be inferred. Trusted producer invocation provenance is required. |

Linker-field quoting is parsed without shell execution; malformed or ambiguous
quoting and arbitrary `-X` targets are refused. These missing/default rules follow
the pinned Go source (`cmd/go/internal/load/pkg.go`, build-info generation and
`setPGOProfilePath`); no absent setting is invented as an observed flag.

Main module/package paths must match the declared package command, with empty
main-module checksum and no main replacement. Main.Version must be nonempty but
is **observed**, not assumed to be `(devel)`: pinned Go may replace that default
with a VCS-derived version and dirty suffix. This version is unauthenticated
metadata, not equality to `go list -m`'s version or proof of source provenance.

Resolver settings (`GOPROXY`, `GOSUMDB`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`,
`GOMODCACHE`) are removed from persisted profiles and represented only by exact
SHA256 equality commitments. These are not authentication, encryption, or a
promise against guessing low-entropy values. No raw resolver values or Origin
URLs are put into the MVS inventory. Subprocess stderr is classified into bounded
static diagnostic categories; unknown details are deliberately withheld rather
than relying on incomplete URL redaction. Published test events retain validated
structural outcomes/names, not arbitrary child Output text. Missing/skip/failure
validation still uses the complete original structured stream before publication.

### Trust boundaries and remaining work

The running command's executable hash/build metadata and the **selected** command
sources are separate evidence: `runner.source_linkage` remains `"UNPROVEN"`.
Binding records the binding runner too and never upgrades that status. Source
hashes do not prove the installed compiler was built from those sources.
The consumer's entire transitive source closure or application behavior is not
proved by these model tests; command-file hashes are not proof that a trusted
producer actually invoked that command. BuildInfo is informational and not an
exhaustive or authenticated record of every possible build input.

External trusted release/deploy verification must supply producer provenance and
final image-digest trust later. No image self-digest, embedded self-hash, signing,
runtime setter, CI integration or full native-budget revision is introduced.
An arm64 build remains an ordinary supported build outside this audited amd64
evidence command; it must not reuse an amd64 success record. The offline proxy
integration test is a controlled fixture, **not genuine consumer release proof**.

## Distinct logical worker producer (currently refuses complete PREBUILD)

`-worker -consumer ROOT -consumer-command ./cmd -go /absolute/go -report FILE`
selects a **separate** fresh-scope-objects-union-stage-v1 logical evidence schema.
It does not change syntax-model records, their false/null qualification markers,
or the syntax linker allowlist. Worker PREBUILD and BUILD always state
`native_activation: NOT_QUALIFIED`.

The parser/init in [`shared_worker_evidence.go`](../../fullruntime/shared_worker_evidence.go),
its direct tests and this tooling form a publication foundation, not the complete
shared-worker implementation. They alone do not provide its coordinator, the
24-byte assertion-site owner or an applicable full-runtime numerical envelope.
The full producer still requires the exact complete runtime sources, required
tests and generated proofs; it refuses missing implementation or unresolved
consumer premises. Publishing this foundation alone leaves native activation
`NOT_QUALIFIED` and does not make `NodeEnforcer.Ready` available.

The source machinery captures the actual selected consumer import/build-input
closure (Go/assembly/embeds/module manifests), fullruntime/fullpolicy trees,
reviewed proof files and selected tool/profile identities. It also captures the
selected toolchain's builtin assembler-header tree and `runtime/cgo/abi_amd64.h`;
compiler-generated `go_asm.h` follows the captured Go types/compiler inputs.
Exact package/test run+pass events are mandatory; skipped, missing, failed or unexpected identities
are not accepted. Complete PREBUILD is currently **unavailable**:
`deriveWorkerTail` still refuses, even though conditional project/dependency
components and their composition are implemented. Final approved-consumer
sentinel assumptions, relevant opaque/unsafe-source disposition, and final
published-source/release provenance remain outstanding. No CLI numeric budget,
passed-artifact JSON or user qualification flag can override that refusal.

On the exact source/tool/profile pins, bootstrap B is536 bytes
(136+16+3*112+3*16). Project-only scratch is the phase maximum of the
1,310,800-byte proc/scope envelope,96-byte metadata phase, and2,507-byte cleanup
command phase (16+1379+1112). The1379-byte caller comprises
32+1112+48+3+56+112+16. Object and union compiler debits remain cumulative,
including failures and deduplication; union output does not escape the operation.
The selected dependency component contributes a conservative maximum of
1,454 bytes across joined command phases, under its fixed source/profile and
startup-cache/sentinel premises. The conditional composition derives
T = 1,310,800 + 1,454 = 1,312,254 and checks B + T = 1,312,790; cumulative compiler
debits remain outside that fixed reservation. These logical ownership terms are
not an allocator, stack or RSS bound, and the composition is not complete worker
evidence. Generated artifact digests identify the corresponding checks; valid
digest syntax alone does not authenticate them.

PREBUILD and BUILD generate fresh selected-runtime, Limited-compiler, dependency
and dependency-stdlib lowering checks using the controlled build, in addition to
the init consumption check.
Exact runtime/helper/compiler/selected-dependency sources and compiler tools are
pinned; supplied artifact hashes cannot substitute for those generated checks.
The dependency calculation applies to the selected temporary Cilium replacement,
`github.com/matthyx/ebpf@v0.0.0-20261030111350-637a2d176be0`, not an assumed upstream
fix or a zero-cost error path. Its applicability includes successful startup
handshake/cache priming and an unchanged `ebpf.ErrNotSupported` sentinel.

Both phases also generate a scoped, type-aware Go sentinel check. It rejects
direct assignments, address-taking and exact-symbol `go:linkname` cases, and
binds its structured result and export hashes to the complete snapshot,
profile/tools and actual runner identity. Its opaque-input inventory is not
approval of arbitrary unsafe or assembly behavior. Older published-consumer
diagnostics with temporary module files are not final consumer/release proof.

A future complete PREBUILD is hashed before deriving the single 366-byte ASCII
carrier. Carrier format is IGW1, scope0001, model0001, profile01(raw empty) or
02(raw greenteagc), five lowercase nonzero SHA256 references (PREBUILD, inputs,
profile, checks, tail proof), then positive16-hex-digit B and T with checked sum.
The exact private linker target is
`github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime.sharedWorkerEvidence`.
Runtime package init consumes the string into a reference-free frozen descriptor;
the default empty carrier refuses admission before bootstrap. Hashes identify
evidence, not authentication. Existing approved signed-image digest verification
remains the external release/deployment trust mechanism.

Controlled BUILD uses `-worker-prebuild FILE -worker-output NEW_EXECUTABLE` in
worker mode. It executes its own fixed go build command with exactly one computed
carrier assignment, validates selected inputs before/after, exact flags/profile/
module BuildInfo, and selected init lowering. It never binds a supplied binary,
executes a consumer/gadget binary, or accepts arbitrary linker overrides. The
pure-Go linked fixture extracts only the actual parser/init and tests normal and
stripped binaries; importing a module or finding carrier text in BuildInfo alone
is not treated as proof that init consumed it.

Startup ownership is separate from per-operation H: the carrier string header
and367-byte linked backing (366 wire bytes plus the linker's trailing NUL),
plus the192-byte frozen descriptor, remain package-owned:575 logical bytes
including the16-byte string header. The wire/parser length remains366.
The emitted assertion-site descriptor adds24 separately owned startup bytes;
neither575 nor their599-byte subtotal claims to inventory all package startup.
Runtime-managed global type/itab caches are outside this logical owner domain.
Those sizes/lowering and all affected worker terms must be rebound to the final
selected producing build. No positive production descriptor or Ready state is
created by these tooling changes.
