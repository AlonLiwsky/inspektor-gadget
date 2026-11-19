// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

// Reviewed proc/scope closure source pins; fork/xsys refresh preserves the
// reviewed phase formula. Current reviewed source/tool manifest SHA256:
// f1770371f000c198d53be39d92a23aa04d00506ea4a9c6e40a0d24d4e4d1eccb.
// Changing a pin requires proof re-review, not merely capturing new bytes.
var workerProcSourcePins = map[string]string{
	"closure/golang.org/x/sys/unix/ioctl_linux.go":          "fd7dbee47ea5f00207bf340db54d294960101f003b6722d31162a06d69f4c4ff",
	"closure/golang.org/x/sys/unix/syscall.go":              "2f1f25726d54e971b2dcedc7e8bc7d109d579e3a671f0ecfabd4deb85246c3be",
	"closure/golang.org/x/sys/unix/syscall_linux.go":        "5cba74fe971377ace2b1192f8d7818f991f3fd8b11e15639960c93b1c5771220",
	"closure/golang.org/x/sys/unix/syscall_unix.go":         "d851dcf05549674486f35d58b0357bb5c1ea9378bd234b1646534a35dc4a6da5",
	"closure/golang.org/x/sys/unix/zsyscall_linux.go":       "8cc4ff6e99f40b57fb5bfdce2e929ba7e6a76fd3d8c9bd7b8c3a564422d37113",
	"closure/golang.org/x/sys/unix/zsyscall_linux_amd64.go": "a492772c3ad8ae8600283c2223289426bfaa3f75666ef62a77914b1ca140f2eb",
	"fullruntime/proc_pin.go":                               "ab92a3dcbbbc4d3bdf9881011685968268a9de780f498e2c6bd4677e02798912",
	"fullruntime/scope.go":                                  "60786eddd173f66ed8463f18e5a049c9ddd021cc0028e0d3a8cfb7624b972df7",
	"fullruntime/shared_binding.go":                         "d1f48fd49f8726b200be35eb17e7c4c8df2f479f48b3fe0d6da09046f4cd0d7c",
	"selected-module/go.mod":                                "8b665620046c95c3f4b9f8f6cf5cbe5ec46ebbb107b58b1d5c821d57fd3fd93b",
	"selected-module/go.sum":                                "e2a4c7ff6d04244fdcaa729afe2873d0bde599c61b329e0ee0630843bd1e7329",
	"toolchain/src/fmt/errors.go":                           "01fd304868493a3aa1198cc79a56274930f687353e9405211ca063c1b8195ea6",
	"toolchain/src/internal/poll/fd.go":                     "39051b29c8a2097c40efe00072247b0bbe4fb2b0e330f504c524de7751e909a0",
	"toolchain/src/internal/poll/fd_unix.go":                "675f74e8cbfc73170e08b43947c131706cd59e498d722555fe3b793618f5f162",
	"toolchain/src/internal/poll/fd_unixjs.go":              "ed73269460d0c3dcd551a2b9caa5c58e5c818a064d2971f8d63b3b13c6fdebe0",
	"toolchain/src/internal/poll/hook_unix.go":              "4a467c97720f9d92849b4d64fd95980f8528d9ae2ac2a50cfc1309ff0759cba0",
	"toolchain/src/internal/strconv/atoi.go":                "bd69756b79c2f007ce7900bea400051f9f9da600c9c6bad656e46900331663d8",
	"toolchain/src/internal/stringslite/strings.go":         "3ed7df2eeabb5427d44b95e6cfe66ef03e13f1c969ad08050a4a0e89d43b8af2",
	"toolchain/src/io/io.go":                                "3945d328a9072e4f5970b7d4bc0eb834eec29fd22889a1ed9f3fb76ad41c3274",
	"toolchain/src/os/file.go":                              "d77653afbcbec5256b56aee25dce3df3ed001f964c9b245b848a5d378884bcb3",
	"toolchain/src/os/file_posix.go":                        "2e93ac5f812cd7184d3ac3a2eb9a51583911a6261cf9c27772fa7dfedcbe514f",
	"toolchain/src/os/file_unix.go":                         "877dd004355c475e8805b5700061604558422da057037556e0cf6edeb36ab7ec",
	"toolchain/src/runtime/iface.go":                        "9c8005e792d0363d3b027975af8f07f2ea2f8d591fccfcb1cd117b29d3e2c8b3",
	"toolchain/src/strconv/number.go":                       "dda43e8c91d95f9dea0c46b2fec6637e5520cae099e40c5965dca0e41bbaab9e",
	"toolchain/src/strings/strings.go":                      "a81bdf73a308277c322e35d0c602e3813f57b6f769c091f8f8962c8884a45ea3",
	"toolchain/src/syscall/syscall_unix.go":                 "7361dc67cc63399a24a39473e0e3b0b02695464236630f6963604991fd1d4873",
	"toolchain/src/syscall/zsyscall_linux_amd64.go":         "9d3d6ce5403a67d06471690e1c0f7ebf36bade8d843c7e3bef31ca2b7acaf80c",
}
