#!/usr/bin/env python3
"""Fail closed if the actual target BTF changes the inode_permission slots."""
import argparse
import json
import subprocess


def check(types):
    by_id = {item["id"]: item for item in types}

    def resolve(type_id):
        item = by_id[type_id]
        while item["kind"] in {"TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG", "DECL_TAG"}:
            item = by_id[item["type_id"]]
        return item

    func = next(item for item in types if item["kind"] == "FUNC" and item["name"] == "bpf_lsm_inode_permission")
    proto = by_id[func["type_id"]]
    assert proto["kind"] == "FUNC_PROTO" and proto["vlen"] == 3, "inode_permission requires idmap, inode, mask"
    params = proto["params"]
    assert [param["name"] for param in params] == ["idmap", "inode", "mask"], "inode_permission argument slots changed"
    for param, name in zip(params[:2], ["mnt_idmap", "inode"]):
        pointer = resolve(param["type_id"])
        assert pointer["kind"] == "PTR", f"{name} argument is not a pointer"
        pointee = resolve(pointer["type_id"])
        assert pointee["kind"] == "STRUCT" and pointee["name"] == name, f"wrong {name} pointee"
    for type_id in [params[2]["type_id"], proto["ret_type_id"]]:
        integer = resolve(type_id)
        assert integer["kind"] == "INT" and integer["size"] == 4 and integer["encoding"] == "SIGNED", "mask/result must be signed int32"

    for name in ["cgroup_can_fork", "cgroup_post_fork", "cgroup_cancel_fork"]:
        func = next(item for item in types if item["kind"] == "FUNC" and item["name"] == name)
        proto = by_id[func["type_id"]]
        assert proto["kind"] == "FUNC_PROTO" and proto["vlen"] == 2, f"{name} requires child, kargs"
        assert [param["name"] for param in proto["params"]] == ["child", "kargs"], f"{name} slots changed"
        for param, expected in zip(proto["params"], ["task_struct", "kernel_clone_args"]):
            ptr = resolve(param["type_id"])
            assert ptr["kind"] == "PTR", f"{name} {expected} is not pointer"
            pointee = resolve(ptr["type_id"])
            assert pointee["kind"] == "STRUCT" and pointee["name"] == expected, f"{name} wrong pointee"
        if name == "cgroup_can_fork":
            ret = resolve(proto["ret_type_id"])
            assert ret["kind"] == "INT" and ret["size"] == 4 and ret["encoding"] == "SIGNED", "can_fork result must be signed int32"
        else:
            assert proto["ret_type_id"] == 0, f"{name} must return void"

    func = next(item for item in types if item["kind"] == "FUNC" and item["name"] == "cgroup_kn_lock_live")
    proto = by_id[func["type_id"]]
    assert proto["kind"] == "FUNC_PROTO" and proto["vlen"] == 2, "ARM hook needs kn and drain_offline"
    assert [param["name"] for param in proto["params"]] == ["kn", "drain_offline"], "ARM argument slots changed"
    for type_id, name in [(proto["params"][0]["type_id"], "kernfs_node"), (proto["ret_type_id"], "cgroup")]:
        pointer = resolve(type_id)
        assert pointer["kind"] == "PTR", f"ARM {name} is not pointer"
        pointee = resolve(pointer["type_id"])
        assert pointee["kind"] == "STRUCT" and pointee["name"] == name, f"ARM wrong {name} pointee"
    boolean = resolve(proto["params"][1]["type_id"])
    assert boolean["kind"] == "INT" and boolean["size"] == 1, "ARM drain_offline bool changed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("btf", help="exact running /sys/kernel/btf/vmlinux or archived raw BTF")
    parser.add_argument("--self-test", action="store_true", help="also reject missing/swapped idmap negative controls")
    args = parser.parse_args()
    types = json.loads(subprocess.check_output(["bpftool", "-j", "btf", "dump", "file", args.btf], text=True))["types"]
    check(types)
    print("PASS: actual BTF inode_permission slots and all three cgroup fork signatures and ARM entry/exit signature")
    if args.self_test:
        func = next(item for item in types if item["kind"] == "FUNC" and item["name"] == "bpf_lsm_inode_permission")
        proto = next(item for item in types if item["id"] == func["type_id"])
        params = proto["params"]
        for name, changed in [("missing idmap", params[1:]), ("swapped idmap/inode", [params[1], params[0], params[2]])]:
            malformed = [dict(item, params=changed, vlen=len(changed)) if item["id"] == proto["id"] else item for item in types]
            try:
                check(malformed)
            except AssertionError:
                print(f"PASS: negative ABI {name} rejected")
            else:
                raise AssertionError(f"malformed ABI accepted: {name}")

        for name in ["cgroup_can_fork", "cgroup_post_fork", "cgroup_cancel_fork", "cgroup_kn_lock_live"]:
            func = next(item for item in types if item["kind"] == "FUNC" and item["name"] == name)
            proto = next(item for item in types if item["id"] == func["type_id"])
            malformed = [dict(item, params=list(reversed(item["params"]))) if item["id"] == proto["id"] else item for item in types]
            try:
                check(malformed)
            except AssertionError:
                print(f"PASS: negative ABI swapped {name} arguments rejected")
            else:
                raise AssertionError(f"malformed ABI accepted: {name}")


if __name__ == "__main__":
    main()
