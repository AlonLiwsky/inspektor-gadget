#!/usr/bin/env python3
"""Check the actual emitted irreversible commit region, without loading BPF."""
import argparse
import re
import subprocess
import struct
from pathlib import Path


def check(text):
    match = re.search(r"<pc_commit_begin>:\n(.*?)\n[^\n]*<pc_commit_end>:", text, re.S)
    assert match, "missing bounded commit labels"
    instructions = [line.split(":\t", 1)[1].strip() for line in match[1].splitlines() if ":\t" in line]
    assert instructions, "empty commit region"
    assert not any(re.search(r"\b(if|goto|call|exit)\b", insn) for insn in instructions), "commit region contains branch/helper/exit"
    # Fail closed on the reviewed Clang 21 shape: eight different stable map
    # pointers, eight actual epoch loads, then the descriptor. This is emitted
    # shape evidence, not a substitute for verifier pointer/lifetime proof.
    targets = []
    for index, offset in enumerate([0x18, 0x38, 0x78, 0x88, 0x98, 0xa8, 0xb8, 0xc8]):
        load, pointer, store = instructions[1 + index * 3:4 + index * 3]
        assert load == f"r1 = *(u64 *)(r0 + {offset:#x})", "missing MAX8 sealed epoch load"
        match = re.fullmatch(r"r2 = \*\(u64 \*\)\(r10 - (0x[0-9a-f]+)\)", pointer)
        assert match, "missing MAX8 prelooked-up pointer reload"
        targets.append(match.group(1))
        assert store == "*(u64 *)(r2 + 0x8) = r1", "missing MAX8 catalogue epoch store"
    assert len(set(targets)) == 8, "MAX8 stores reuse a catalogue pointer spill"
    assert sum(insn.startswith("*(u64 *)") for insn in instructions) == 17, "unexpected MAX8 authority store count"


def check_stage_bounds(text):
    """Require the address-taken bank reload to be rejected before ownership.

    This is an emitted-code regression check, not verifier/dataflow proof.
    Fail closed if the compiler changes the instruction shape for review.
    """
    stage = text.split("<stage_task>:\n", 1)[1].split("\n\n", 1)[0]
    lookup = stage.index("call 0x1\n")
    lock = stage.index("call 0x5d\n", lookup)
    prefix = stage[lookup:lock]
    reload = re.search(r"([rw]\d+) = \*\(u32 \*\)\(r10 - (0x[0-9a-f]+)\)", prefix)
    assert reload, "missing post-lookup bank reload"
    reg = reload.group(1)
    assert re.search(r"if " + reg + r" > 0x1 goto \+0x[0-9a-f]+", prefix[reload.end():]), "missing post-lookup invalid-bank rejection"
    assert "-0x16" in prefix, "missing EINVAL rejection result"
    # The guarded register, not a second unconstrained stack reload, must form
    # the history pointer before the first ownership lock/helper.
    assert re.search(r"w1 = " + reg + r"\n\s*\d+:\tr1 \*= 0x50\n\s*\d+:\tr8 = r7\n\s*\d+:\tr8 \+= r1\n\s*\d+:\tr8 \+= 0x30", prefix), "history pointer not formed from checked bank before ownership"



def check_line_info(path):
    """Validate raw ELF64 BTF.ext line offsets without rewriting metadata.

    This fixture's relocatable BPF line offsets are section-relative bytes.
    Duplicate raw offsets cannot become distinct instruction offsets at load.
    """
    data = Path(path).read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64"
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    def string(table, start):
        return table[start:].split(b"\0", 1)[0].decode()
    sections = {string(names, h[0]): data[h[4]:h[4] + h[5]] for h in headers}
    btf, ext = sections[".BTF"], sections[".BTF.ext"]
    btf_header = struct.unpack_from("<I", btf, 4)[0]
    strings_offset, strings_size = struct.unpack_from("<II", btf, 16)
    strings = btf[btf_header + strings_offset:btf_header + strings_offset + strings_size]
    ext_header = struct.unpack_from("<I", ext, 4)[0]
    line_offset, line_size = struct.unpack_from("<II", ext, 16)
    cursor, end = ext_header + line_offset, ext_header + line_offset + line_size
    record_size = struct.unpack_from("<I", ext, cursor)[0]
    assert record_size >= 16 and line_size > 4, "missing BTF line evidence"
    cursor += 4
    while cursor < end:
        name_offset, records = struct.unpack_from("<II", ext, cursor)
        cursor += 8
        section = string(strings, name_offset)
        previous = -1
        for index in range(records):
            insn = struct.unpack_from("<I", ext, cursor)[0]
            assert previous < insn < len(sections[section]) and insn % 8 == 0, f"invalid BTF line offset {section}[{index}]: {insn}, previous {previous}"
            previous = insn
            cursor += record_size
    assert cursor == end, "malformed BTF line section"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    check_line_info(args.object)
    print("PASS: raw BTF.ext line offsets strictly increase within each section")
    text = subprocess.check_output(["llvm-objdump", "-d", "--no-show-raw-insn", args.object], text=True)
    symbols = subprocess.check_output(["readelf", "-s", args.object], text=True)
    for name in ["pc_commit_begin", "pc_commit_end"]:
        assert re.search(r"\bNOTYPE\s+GLOBAL\s+DEFAULT\s+\d+\s+" + name + r"\b", symbols), "commit label must not introduce an extra BPF program"
    check(text)
    check_stage_bounds(text)
    print("PASS: emitted staging bank reload has rejection guard before ownership")
    print("PASS: emitted commit has exactly eight distinct catalogue pointer epoch stores, nine descriptor/receipt/metric stores, and no branch/helper/exit")
    if args.self_test:
        region = re.search(r"<pc_commit_begin>:\n(.*?)\n[^\n]*<pc_commit_end>:", text, re.S).group(1)
        epoch_stores = list(re.finditer(r"^.*\*\(u64 \*\)\(r2 \+ 0x8\) = r1$", region, re.M))
        assert len(epoch_stores) == 8
        bad_region = region[:epoch_stores[-1].start()] + region[epoch_stores[-1].end():]
        try:
            check(text.replace(region, bad_region, 1))
        except (AssertionError, ValueError):
            print("PASS: negative missing eighth catalogue epoch store rejected")
        else:
            raise AssertionError("seven-epoch commit accepted")
        stage_start = text.index("<stage_task>:\n")
        lookup = text.index("call 0x1\n", stage_start)
        bad = text[:lookup] + re.sub(r"if ([rw]\d+) > 0x1 goto", r"if \1 > 0x2 goto", text[lookup:], count=1)
        try:
            check_stage_bounds(bad)
        except AssertionError:
            print("PASS: negative weakened staging bank bound rejected")
        else:
            raise AssertionError("weakened staging bound accepted")
        for name, instruction in [("helper", "call 0x1"), ("conditional", "if r0 == 0x0 goto +0x1"), ("jump", "goto +0x1"), ("early exit", "exit")]:
            bad = text.replace("<pc_commit_begin>:\n", "<pc_commit_begin>:\n     0:\t" + instruction + "\n", 1)
            try:
                check(bad)
            except AssertionError:
                print("PASS: negative commit " + name + " rejected")
            else:
                raise AssertionError("malformed commit accepted: " + name)


if __name__ == "__main__":
    main()
