#!/usr/bin/env python3
"""Fail when a binary's UniFFI exports disagree with the generated bindings.

    scripts/check_ffi_exports.py [--bindings FILE] [--load] BINARY...

Every generated binding (`pubkycoreFFI.h`, `pubkycore.kt`, `pubkycore.swift`, `pubkycore.py`)
names each exported function as `uniffi_pubkycore_fn_func_<name>` and resolves it at load, or at
link. A binary built from another commit — a merge that resolved a row to the other branch's
build, a CI artifact downloaded for the wrong head — exports a different set, and nothing else
notices until a consumer's first call: JNA's `UnsatisfiedLinkError`, an Xcode link failure, a
Python `AttributeError`. This compares the sets, so a binary row cannot be silently swapped.

Names are not the whole contract: a signature change that keeps a function's name changes its
`uniffi_pubkycore_checksum_*` value, which every binding compares at load. Those values are
constants returned by functions, so reading them means calling them; `--load` does that for a
binary this host can load (the desktop row for its own OS) and compares each with the value the
binding embeds. The Android and iOS rows cannot be loaded on a CI runner and get the name check
only. Neither check can tell a stale build whose FFI surface did not change from a fresh one —
nothing in the binary says which commit it came from — so that is left to building every row
from source in CI and committing exactly what it uploaded.

Only the standard library, so it runs the same on every CI row and inside the build scripts.
"""

import argparse
import ctypes
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


# `if lib.uniffi_pubkycore_checksum_func_auth() != 51826:` in Python, the same with `.toShort()`
# in Kotlin and in parentheses in Swift: the name and the value the binding expects.
CHECKSUM = re.compile(rb"(uniffi_pubkycore_checksum_(?:func|method)_[a-z0-9_]+)\(\)\s*!=\s*(\d+)")


def checksums_in(path: Path) -> dict[str, int]:
    return {name.decode(): int(value) for name, value in CHECKSUM.findall(path.read_bytes())}


def checksum_mismatches(binary: Path, expected: dict[str, int]) -> list[str]:
    """Load `binary` and call every checksum function the binding names."""
    try:
        lib = ctypes.CDLL(str(binary.resolve()))
    except OSError as error:
        return [f"cannot load: {error}"]
    problems = []
    for name, value in sorted(expected.items()):
        try:
            function = getattr(lib, name)
        except AttributeError:
            problems.append(f"missing  {name}")
            continue
        function.argtypes = []
        function.restype = ctypes.c_uint16
        actual = function()
        if actual != value:
            problems.append(f"checksum {name}: binary {actual}, binding {value}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--bindings",
        default="bindings/ios/pubkycoreFFI.h",
        help="a generated binding to take the expected function list from (default: the C header)",
    )
    parser.add_argument(
        "--load",
        action="store_true",
        help="also load each binary and compare its checksum values with the binding's "
        "(only for a binary built for this host; needs a binding that embeds the values, "
        "i.e. not the C header)",
    )
    parser.add_argument("binaries", nargs="+", help="dylib, so, dll or static archive to check")
    args = parser.parse_args()

    bindings = Path(args.bindings)
    expected = names_in(bindings)
    if not expected:
        print(f"{bindings}: no uniffi_pubkycore_*_func_ names found", file=sys.stderr)
        return 2
    print(f"{bindings}: {len(expected)} exports expected")
    expected_values = checksums_in(bindings) if args.load else {}
    if args.load:
        if not expected_values:
            print(f"{bindings}: no checksum values to compare (use a .kt, .swift or .py binding)",
                  file=sys.stderr)
            return 2
        print(f"{bindings}: {len(expected_values)} checksum values expected")

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
        values = checksum_mismatches(binary, expected_values) if args.load else []
        if missing or extra or values:
            failed = True
            print(f"{binary}: MISMATCH against {bindings}", file=sys.stderr)
            for name in missing:
                print(f"  missing  {name.decode()}", file=sys.stderr)
            for name in extra:
                print(f"  extra    {name.decode()}", file=sys.stderr)
            for problem in values:
                print(f"  {problem}", file=sys.stderr)
        else:
            checked = f", {len(expected_values)} checksum values" if args.load else ""
            print(f"{binary}: ok ({len(actual & expected)} exports{checked})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
