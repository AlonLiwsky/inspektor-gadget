#!/usr/bin/env python3
"""Offline check of embedded registration data, not module load acceptance."""
import pathlib
import re
import struct
import subprocess
import sys
import tempfile


def validate(ids, dump):
    if len(ids) != 16:
        raise ValueError("expected exactly one set8 entry and no trailing IDs")
    count, set_flags, function_id, flags = struct.unpack("<4I", ids)
    if count != 1 or set_flags != 1 or function_id == 0 or flags != 0x30:
        raise ValueError("invalid count/set flags/function ID/KF flags")
    matches = re.findall(r"^\[(\d+)\] FUNC 'ig_capture_pending_argv' type_id=\d+ linkage=\w+$", dump, re.M)
    if matches != [str(function_id)]:
        raise ValueError("embedded function ID does not match validated split BTF")


def validate_arg0(base_dump, dump):
    """Require a pointer to the base BTF type, not a same-named split type."""
    def entries(text):
        return {int(m.group(1)): m.group(2) for m in re.finditer(
            r"^\[(\d+)\] (.*?)(?=^\[|\Z)", text, re.M | re.S)}
    base, combined = entries(base_dump), entries(dump)
    canonical = [i for i, body in base.items()
                 if body.startswith("STRUCT 'linux_binprm' ")]
    if len(canonical) != 1:
        raise ValueError("missing or ambiguous base-kernel linux_binprm")
    funcs = [body for body in combined.values()
             if body.startswith("FUNC 'ig_capture_pending_argv' ")]
    if len(funcs) != 1:
        raise ValueError("missing or ambiguous kfunc")
    proto_id = int(re.search(r"type_id=(\d+)", funcs[0]).group(1))
    proto = combined.get(proto_id, "")
    if not proto.startswith("FUNC_PROTO "):
        raise ValueError("missing kfunc prototype")
    args = re.findall(r"^\s+'[^']*' type_id=(\d+)$", proto, re.M)
    if len(args) != 3:
        raise ValueError("unexpected kfunc argument count")
    pointer = combined.get(int(args[0]), "")
    match = re.fullmatch(r"PTR '[^']*' type_id=(\d+)\s*", pointer)
    if not match or int(match.group(1)) != canonical[0]:
        raise ValueError("kfunc arg0 is not canonical base-kernel linux_binprm identity")


def check(module):
    with tempfile.TemporaryDirectory(prefix="ig-argv-structural-") as directory:
        root = pathlib.Path(directory)
        for section in (".BTF", ".BTF.base", ".BTF_ids"):
            subprocess.run(["objcopy", "--dump-section", f"{section}={root / section}", str(module)], check=True)
            if not (root / section).stat().st_size:
                raise ValueError(f"empty embedded {section}")
        # Parse the embedded distilled base and embedded split BTF together.
        dump = subprocess.check_output(["bpftool", "-B", str(root / ".BTF.base"), "btf", "dump", "file", str(root / ".BTF"), "format", "raw"], text=True)
        validate((root / ".BTF_ids").read_bytes(), dump)
        base_dump = subprocess.check_output(["bpftool", "btf", "dump", "file", str(root / ".BTF.base"), "format", "raw"], text=True)
        validate_arg0(base_dump, dump)
    print(f"PASS embedded BTF/set8: {module}")


if __name__ == "__main__":
    check(pathlib.Path(sys.argv[1]).resolve())
