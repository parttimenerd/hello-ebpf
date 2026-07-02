#!/usr/bin/env python3
"""
Extract per-kind struct_ops layouts as JSON.

Usage:
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
    python3 scripts/extract-struct-ops-layouts.py /tmp/vmlinux.h \
        bpf-compiler-plugin/src/main/resources/struct-ops-layouts/

Writes one <kernelName>.json per supported kind. Overwrites existing files.
"""

import json
import re
import sys
from pathlib import Path

TARGETS = {
    "sched_ext_ops":     "6.12",
    "tcp_congestion_ops": "5.6",
    "Qdisc_ops":         "6.10",
    "hid_bpf_ops":       "6.11",
}

STRUCT_RE = re.compile(
    r"struct\s+(\w+)\s*\{(.+?)\}\s*;",
    re.DOTALL,
)
FUNCPTR_RE = re.compile(
    r"^\s*(?P<ret>[\w\s\*]+?)\s*\(\s*\*\s*(?P<name>\w+)\s*\)\s*\((?P<args>.*?)\)\s*;",
    re.DOTALL,
)
DATA_RE = re.compile(
    r"^\s*(?P<type>[\w\s\*]+?)\s+(?P<name>\w+)(?P<arr>\[\d+\])?\s*;",
)

def parse_args(argstr: str):
    argstr = argstr.strip()
    if argstr == "" or argstr == "void":
        return []
    out = []
    depth = 0
    cur = []
    for ch in argstr + ",":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            piece = "".join(cur).strip()
            if piece:
                m = re.match(r"^(.+?)(\w+)\s*$", piece)
                if m:
                    type_part = m.group(1).strip()
                    name_part = m.group(2).strip()
                    if type_part.endswith("*") or " " in type_part:
                        out.append({"name": name_part, "type": type_part})
                    else:
                        out.append({"name": "arg" + str(len(out)), "type": piece})
                else:
                    out.append({"name": "arg" + str(len(out)), "type": piece})
            cur = []
            continue
        cur.append(ch)
    return out

def extract(vmlinux_c: str, kind: str):
    for match in STRUCT_RE.finditer(vmlinux_c):
        name = match.group(1)
        if name != kind:
            continue
        body = match.group(2)
        fields = []
        depth = 0
        cur = []
        raw_fields = []
        for ch in body + ";":
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == ";" and depth == 0:
                piece = "".join(cur).strip()
                if piece:
                    raw_fields.append(piece + ";")
                cur = []
                continue
            cur.append(ch)
        for raw in raw_fields:
            fm = FUNCPTR_RE.match(raw)
            if fm:
                fields.append({
                    "name": fm.group("name"),
                    "kind": "function",
                    "returnType": fm.group("ret").strip(),
                    "args": parse_args(fm.group("args")),
                })
                continue
            dm = DATA_RE.match(raw)
            if dm:
                t = dm.group("type").strip()
                arr = dm.group("arr") or ""
                fields.append({
                    "name": dm.group("name"),
                    "kind": "data",
                    "returnType": t + arr,
                    "args": [],
                })
        return fields
    return None

def main():
    if len(sys.argv) != 3:
        print("usage: extract-struct-ops-layouts.py <vmlinux.h> <out-dir>", file=sys.stderr)
        sys.exit(2)
    vmlinux_h = Path(sys.argv[1]).read_text()
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    for kind, since in TARGETS.items():
        fields = extract(vmlinux_h, kind)
        if fields is None:
            print(f"warn: struct {kind} not found in vmlinux; skipping", file=sys.stderr)
            continue
        payload = {"kernelName": kind, "since": since, "fields": fields}
        out = out_dir / f"{kind}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {out} ({len(fields)} fields)")

if __name__ == "__main__":
    main()
