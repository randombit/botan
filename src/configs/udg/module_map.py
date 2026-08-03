#!/usr/bin/env python3

"""
Emit a udg module map (generic JSON schema) from Botan's per-module
info.txt metadata.
"""

import json
import sys
from pathlib import Path


def parse_info(path: Path) -> dict:
    """Parse info.txt into {tag: [lines]}. Lines outside tags ignored."""
    sections = {}
    current = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("</"):
            current = None
        elif line.startswith("<") and line.endswith(">"):
            current = line[1:-1]
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def main() -> None:
    args = sys.argv[1:]
    excluded = set()
    if "--exclude" in args:
        i = args.index("--exclude")
        excluded = set(args[i + 1 :])
        args = args[:i]
    if len(args) != 1:
        sys.exit("usage: botan_module_map.py <botan-dir> [--exclude mod ...]")
    botan = Path(args[0])
    lib = botan / "src" / "lib"
    build_pub = botan / "build" / "include" / "public" / "botan"
    if not build_pub.is_dir():
        sys.exit(f"{build_pub} missing: run ./configure.py in {botan} first")

    modules = []
    for info in sorted(lib.rglob("info.txt")):
        mdir = info.parent
        mid = str(mdir.relative_to(lib))
        if any(mid == e or mid.startswith(e + "/") for e in excluded):
            continue
        sections = parse_info(info)

        meta = {}
        for line in sections.get("module_info", []):
            if "->" in line:
                key, val = line.split("->", 1)
                meta[key.strip()] = val.strip().strip('"')

        headers = [
            str((mdir / h).resolve())
            for h in sections.get("header:public", [])
            if (build_pub / h).exists()
        ]

        parent = mdir.parent
        module = {
            "id": str(mdir.relative_to(lib)),
            "name": meta.get("name", mdir.name),
        }
        if meta.get("brief"):
            module["brief"] = meta["brief"]
        if parent != lib and (parent / "info.txt").exists():
            module["parent"] = str(parent.relative_to(lib))
        module["headers"] = headers
        modules.append(module)

    json.dump({"modules": modules}, sys.stdout, indent=1)


main()
