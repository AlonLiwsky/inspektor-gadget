#!/usr/bin/env python3
"""Validate the real cgroup-mutex ARM endpoint's BTF before loading a fixture."""
import argparse
import copy
import json
import subprocess


def check(types):
    by_id = {t["id"]: t for t in types}

    def resolve(i):
        t = by_id[i]
        while t["kind"] in {"TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG", "DECL_TAG"}:
            t = by_id[t["type_id"]]
        return t

    def pointer(i, name):
        t = resolve(i)
        assert t["kind"] == "PTR", "expected pointer to " + name
        t = resolve(t["type_id"])
        assert t["kind"] == "STRUCT" and t["name"] == name, "wrong pointee: " + name

    f = next(t for t in types if t["kind"] == "FUNC" and t["name"] == "cgroup_kn_lock_live")
    proto = by_id[f["type_id"]]
    assert proto["kind"] == "FUNC_PROTO" and proto["vlen"] == 2, "ARM hook needs kn and drain_offline"
    pointer(proto["params"][0]["type_id"], "kernfs_node")
    boolean = resolve(proto["params"][1]["type_id"])
    assert boolean["kind"] == "INT" and boolean["size"] == 1, "drain_offline bool ABI changed"
    pointer(proto["ret_type_id"], "cgroup")
    return f["type_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("btf")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    types = json.loads(subprocess.check_output(["bpftool", "-j", "btf", "dump", "file", args.btf], text=True))["types"]
    proto_id = check(types)
    print("PASS: ARM BTF is cgroup_kn_lock_live(kernfs_node *, bool) -> cgroup *")
    if args.self_test:
        for name in ["arity", "swapped args", "wrong return"]:
            bad = copy.deepcopy(types)
            proto = next(t for t in bad if t["id"] == proto_id)
            if name == "arity":
                proto["vlen"] = 1
                proto["params"] = proto["params"][:1]
            elif name == "swapped args":
                proto["params"].reverse()
            else:
                proto["ret_type_id"] = proto["params"][0]["type_id"]
            try:
                check(bad)
            except AssertionError:
                print("PASS: negative ARM ABI " + name + " rejected")
            else:
                raise AssertionError("malformed ARM ABI accepted: " + name)


if __name__ == "__main__":
    main()
