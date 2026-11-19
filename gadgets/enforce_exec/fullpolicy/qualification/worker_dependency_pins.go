// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

// Conditional dependency component base review source manifest
// 4dc07f42cdc80223ec9ab1a21e1df132c724d1783fc266b64946c3c0d1999dc1.
// Includes successful handshake/cache priming, scalarized joined-error lifetimes,
// the exact Linux reflection Index optimization and byte-slice growth premises.
// These pins do NOT establish consumer sentinel nonmutation or refresh the
// separate project/proc proof. Changing one requires a derivation review.
// Verbatim evidence-boundary extraction delta manifest SHA256:
// 1ebf9cda190ba5e11542494f14c647c4d07cbd2cd249e770ad163228ef9b52ce.
var workerDependencySourcePins = map[string]string{
	"closure/github.com/cilium/ebpf/internal/feature.go":           "092a0d79c739dbdab816001a0d23f6cbe8143ee3946aa8ca453e5acf5576bbf9",
	"closure/github.com/cilium/ebpf/internal/sys/error_message.go": "6b89f7ebfade5fc49ec9e6141238182289f6cad19f910027d9cade389fd44f1f",
	"closure/github.com/cilium/ebpf/internal/sys/signals.go":       "522ab871716cb51beb9c4b691dbe4ca43389580e45aa481932c1a6dbecd197ee",
	"closure/github.com/cilium/ebpf/internal/sys/syscall.go":       "1b58e81d44b8836ac5a5acc52e7bfc1b348bacb08d44ac7a23716cbcb80379c8",
	"closure/github.com/cilium/ebpf/internal/sys/syscall_other.go": "4c134f28deeeb8878b19ae59fe2426012f4a9a696d3f51e039243c11238feb47",
	"closure/github.com/cilium/ebpf/internal/sys/token.go":         "c3545a63bf2d47ec28055964530534a05d31a56f2c71e73426abb71c31d34431",
	"closure/github.com/cilium/ebpf/internal/sys/types.go":         "4c161306bc91b4de657ef46260e690d54c04422a7ed5c906b899bc805f785c79",
	"closure/github.com/cilium/ebpf/internal/sysenc/buffer.go":     "9628f4883abe3057cfaa5015521fee423465b4e3281c4e5e76de67058fa5403e",
	"closure/github.com/cilium/ebpf/internal/sysenc/layout.go":     "2d8522d6bb40228e336ce3270b3f00755c4da9855fbfe7cf149120f6599e16a9",
	"closure/github.com/cilium/ebpf/internal/sysenc/marshal.go":    "36e8c688c77836410b0418d57150b3b7e160177f42bbc79c95d54d688d9049bc",
	"closure/github.com/cilium/ebpf/internal/unix/errno_linux.go":  "988fc893f2277a9590e470a90873c60e102616f744fbe5fe6720f905b50132b6",
	"closure/github.com/cilium/ebpf/internal/unix/error.go":        "584c476db6c4ecb861f4be09440217f77750c2ef8d1fe61bd263223dd0bf485c",
	"closure/github.com/cilium/ebpf/internal/unix/types_linux.go":  "d9af6e3fc1a4ea28c7375fe250404de0112d0889a164feec01bdb04ae963ef5d",
	"closure/github.com/cilium/ebpf/map.go":                        "8e6af3dc70f59851ec08b1bfb6d53e5f42e02ba8987bc40fba18806b4c69a9e8",
	"closure/github.com/cilium/ebpf/marshalers.go":                 "d025e9b3cbd1e1825463f3fd5688177ee9321a614b1dfa26ff96f8a1f186ac9c",
	"closure/github.com/cilium/ebpf/operation_error.go":            "c8c7b534d063aef2f1deaef045fcb5cd3614fb1d928076a65507adad9fe32794",
	"closure/github.com/cilium/ebpf/prog.go":                       "62d5a5951e9bdd64e4e6cc0d98da6f410a8afd5f1f8ce382b773d5f0694078e5",
	"closure/github.com/cilium/ebpf/syscalls.go":                   "583990604a884bf0bb76c2dd3b09b6bdde23a53bfe4db084df11ba69259bc355",
	"closure/github.com/cilium/ebpf/types.go":                      "1e4cd213e8cce772a111378a49484d991efb8962882b243afa5736f6109154f0",
	"closure/github.com/cilium/ebpf/types_string.go":               "5705e4b0ce1b8cf80413bb7c2b1af5907cfcda91587ef57f386c0dc08f0987bc",
	"closure/golang.org/x/sys/unix/syscall.go":                     "2f1f25726d54e971b2dcedc7e8bc7d109d579e3a671f0ecfabd4deb85246c3be",
	"closure/golang.org/x/sys/unix/syscall_linux.go":               "5cba74fe971377ace2b1192f8d7818f991f3fd8b11e15639960c93b1c5771220",
	"closure/golang.org/x/sys/unix/syscall_unix.go":                "d851dcf05549674486f35d58b0357bb5c1ea9378bd234b1646534a35dc4a6da5",
	"closure/golang.org/x/sys/unix/zsyscall_linux.go":              "8cc4ff6e99f40b57fb5bfdce2e929ba7e6a76fd3d8c9bd7b8c3a564422d37113",
	"closure/golang.org/x/sys/unix/zsyscall_linux_amd64.go":        "a492772c3ad8ae8600283c2223289426bfaa3f75666ef62a77914b1ca140f2eb",
	"fullpolicy/kernel.go":                                         "efb567d883b47222a5e72df1b4a1f3d74cd3c03b6a2ecaba6107ab9427658db9",
	"fullruntime/control.go":                                       "7048875c5ef5086f5b8d697aa8f72db69a28696d2615ead9f4bb9fb90c0aa883",
	"fullruntime/shared_host.go":                                   "8487b42bde5371911a0d8d621c0a849fe777a8aa665fac1aa63c453e68c03e84",
	"fullruntime/shared_native_control.go":                         "5e76fab0d859e40016b65591d4cc08baf99728364aea1d61e281c8fd79ef6750",
	"fullruntime/shared_objects.go":                                "742d3b59e31cf6d7e28cd19ae4550687d1919facc5ae3a7585146a1e6abba712",
	"fullruntime/shared_private_outcome.go":                        "0126f4e35dc73e9df837b411520f717ead27e507f808c378c1c040f4d349eb1f",
	"fullruntime/shared_resources.go":                              "9f701ee5d03f565ce5f4f554e4bf100dc494cadbf18347c376a8bef2ee0136cb",
	"fullruntime/shared_snapshot_candidate.go":                     "e2585abc1fed7a962be1eb8ce533bb39eda1f999cebd4e0c85e2d01810da4ea7",
	"fullruntime/shared_worker_evidence.go":                        "3fc7b1d905c91c905cc07fd7904eb3917dafd0e8172820ec444b35c5d18f1115",
	"fullruntime/shared_worker_integration.go":                     "583ba12706a35d995b86b2981f96846cd72c9e4bc4cf9d801913c5c8985d3ea8",
	"fullruntime/shared_worker_result.go":                          "4d49e8d0b642c47c3327ab17859b5ef541b39e4a52a3c781689939c463f6915f",
	"module/github.com/matthyx/ebpf/go.mod":                        "e68b0c504bc7076740a1635e50b24864ebb8e7754300e1ec8294883e63981728",
	"module/golang.org/x/sys/go.mod":                               "9522f4c9806d1c26586ea80fa56292929bd295865e71981927f52996c6b1c831",
	"toolchain/src/encoding/binary/binary.go":                      "fc4fab16ee184c5eaafb75c2e2b8728c9dd04228f96ec8d394c9d3110f9c91df",
	"toolchain/src/errors/wrap.go":                                 "098116636610ae87dd80e49c4dbe6a2b6c37918d7e1af35ded005be621d68a40",
	"toolchain/src/internal/runtime/gc/sizeclasses.go":             "7626b00bbb416c25c5279b29aa73a072d74ace3444e58b178a6ff855a2deec2c",
	"toolchain/src/internal/strconv/itoa.go":                       "d84e249b4334bab64a916061a45366a2d77becf6f4e5cf9d917527efddfc245f",
	"toolchain/src/reflect/type.go":                                "8ed9d931a7e5606ba747f86aca2d7618d8a895dcf1b5a4bdf8a5af03cc4705ca",
	"toolchain/src/reflect/value.go":                               "8178ade44511222a6ec81b4744acdcd4b62819064a1b716450d5d908c4b9c444",
	"toolchain/src/runtime/iface.go":                               "9c8005e792d0363d3b027975af8f07f2ea2f8d591fccfcb1cd117b29d3e2c8b3",
	"toolchain/src/runtime/msize.go":                               "0164d15295726608812842b429e241f553a314985a7c6aa48cb1ad24346a52dd",
	"toolchain/src/runtime/slice.go":                               "ac595f1a822620fdc52271ef84f06b19c1f0abc0e53c0eb049dbad90b86abdbd",
	"toolchain/src/runtime/string.go":                              "7e42368d5ba47af61c75e48334d9001ec0c17905cb9163d00f923d4cba3d3a69",
	"toolchain/src/slices/slices.go":                               "f31f8ff279a51850aa90f3cbf60f06eaf6d5452889e2b015043c91ccb3e5d403",
	"toolchain/src/sync/map.go":                                    "ea2b7b418426ba83ed9b77c5926dcb28a6a94dc84b26ea7b581c782a36a646b4",
	"toolchain/src/syscall/syscall_unix.go":                        "7361dc67cc63399a24a39473e0e3b0b02695464236630f6963604991fd1d4873",
	"toolchain/src/syscall/zerrors_linux_amd64.go":                 "2d96a92f48c420b427f48090663c854672433142fe7c6f7d67638e1e7113a173",
}
