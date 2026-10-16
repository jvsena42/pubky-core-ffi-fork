#!/usr/bin/env python3
"""Fail when a binary's UniFFI exports disagree with the generated bindings.

    scripts/check_ffi_exports.py [--bindings FILE] BINARY...

Every generated binding (`pubkycoreFFI.h`, `pubkycore.kt`, `pubkycore.swift`, `pubkycore.py`)
names each exported function as `uniffi_pubkycore_fn_func_<name>` and resolves it at load, or at
link. A binary built from another commit — a merge that resolved a row to the other branch's
build, a CI artifact downloaded for the wrong head — exports a different set, and nothing else
notices until a consumer's first call: JNA's `UnsatisfiedLinkError`, an Xcode link failure, a
Python `AttributeError`. This compares the sets, so a binary row cannot be silently swapped.

Only the standard library, so it runs the same on every CI row and inside the build scripts.
"""

import argparse
import re
import sys
from pathlib import Path

NAME = re.compile(rb"uniffi_pubkycore_(?:fn|checksum)_func_[a-z0-9_]+")
# Rust's legacy mangling appends `17h<16 hex>E` to a symbol's path segments; an object file in
# a static archive keeps those for internal symbols, and the regex above would read the hash as
# part of the name.
MANGLED_TAIL = re.compile(rb"\d+h[0-9a-f]{16}$")


def names_in(path: Path) -> set[bytes]:
    found = set(NAME.findall(path.read_bytes()))
    return {name for name in found if not MANGLED_TAIL.search(name)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--bindings",
        default="bindings/ios/pubkycoreFFI.h",
        help="a generated binding to take the expected function list from (default: the C header)",
    )
    parser.add_argument("binaries", nargs="+", help="dylib, so, dll or static archive to check")
    args = parser.parse_args()

    bindings = Path(args.bindings)
    expected = names_in(bindings)
    if not expected:
        print(f"{bindings}: no uniffi_pubkycore_*_func_ names found", file=sys.stderr)
        return 2
    print(f"{bindings}: {len(expected)} exports expected")

    failed = False
    for binary in map(Path, args.binaries):
        actual = names_in(binary)
        missing = sorted(expected - actual)
        # A static archive's string tables are not always NUL-separated, so a name can run into
        # the bytes after it (`…_func_auths_0`). Only a token that extends no expected name is a
        # genuine extra; the missing side, which is what a swapped row produces, is exact.
        extra = sorted(
            name
            for name in actual - expected
            if not any(name.startswith(known) for known in expected)
        )
        if missing or extra:
            failed = True
            print(f"{binary}: MISMATCH against {bindings}", file=sys.stderr)
            for name in missing:
                print(f"  missing  {name.decode()}", file=sys.stderr)
            for name in extra:
                print(f"  extra    {name.decode()}", file=sys.stderr)
        else:
            print(f"{binary}: ok ({len(actual & expected)} exports)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
