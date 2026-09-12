#!/bin/bash

# Desktop cdylibs, for JVM consumers that load this crate through JNA.
#
# The Android and iOS scripts beside this one produce artifacts for a *packaged app*; this one
# produces the three rows a desktop client needs (loopky#54, loopky#301):
#
#   linux-x86-64/libpubkycore.so       — where a headless agent actually runs. The primary row.
#   darwin-aarch64/libpubkycore.dylib  — the developer's machine. Apple Silicon only.
#   win32-x86-64/pubkycore.dll         — no `lib` prefix, because JNA does not expect one there.
#
# The directory names are not ours to choose: they are JNA's own resource layout
# (`Platform.getNativeLibraryResourcePrefix()`), so a consumer that drops these into its jar gets
# `Native.load("pubkycore")` working with no install step and no `-Djna.library.path`.
#
# Intel Macs are not a target. One `darwin-aarch64` row rather than two plus a `lipo`, and a
# consumer is expected to refuse an x86-64 Mac with a clear message rather than ship a jar whose
# JNA lookup misses and reports a transport error.

set -euo pipefail

OUT_DIR="./bindings/desktop"
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

usage() {
    cat <<'USAGE'
Usage: ./build_desktop.sh {linux|macos|windows|all}

  linux   x86_64-unknown-linux-gnu -> bindings/desktop/linux-x86-64/libpubkycore.so
          Built natively on Linux. On macOS it cross-builds in a container (see below).
  macos   aarch64-apple-darwin     -> bindings/desktop/darwin-aarch64/libpubkycore.dylib
          macOS on Apple Silicon only.
  windows x86_64-pc-windows-msvc   -> bindings/desktop/win32-x86-64/pubkycore.dll
          Windows only, under Git Bash. Needs the MSVC toolchain; there is no cross build.
  all     Every row this host can produce.
USAGE
}

# --- linux ------------------------------------------------------------------

build_linux_native() {
    echo "Building x86_64-unknown-linux-gnu natively..."
    rustup target add x86_64-unknown-linux-gnu
    cargo build --release --target x86_64-unknown-linux-gnu
    install_artifact \
        "target/x86_64-unknown-linux-gnu/release/libpubkycore.so" \
        "linux-x86-64/libpubkycore.so" \
        strip
}

# Cross-build from a non-Linux host.
#
# An arm64 container with the x86_64 cross-linker, **not** an emulated amd64 one: rustc runs at
# native speed and only the link step is cross, which is the difference between about a minute and
# most of an hour. `ring` and `blake3` need a C compiler for the target, which is what
# gcc-x86-64-linux-gnu provides along with the target libc.
build_linux_in_container() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Error: cross-building Linux from $HOST_OS needs Docker (or run this on Linux)." >&2
        echo "       Alternative: brew install zig && cargo install cargo-zigbuild" >&2
        exit 1
    fi
    echo "Cross-building x86_64-unknown-linux-gnu in a container..."
    docker run --rm \
        -v "$PWD":/src -w /src \
        -v pubkycore-cargo-registry:/usr/local/cargo/registry \
        -v pubkycore-cargo-git:/usr/local/cargo/git \
        rust:1-bookworm bash -c '
            export PATH=/usr/local/cargo/bin:$PATH
            set -e
            apt-get update -qq
            apt-get install -y -qq gcc-x86-64-linux-gnu >/dev/null
            rustup target add x86_64-unknown-linux-gnu
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
            export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
            export AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar
            # A separate target dir so a host build and a cross build do not evict each other.
            cargo build --release --target x86_64-unknown-linux-gnu --target-dir /src/target/xbuild
            x86_64-linux-gnu-strip /src/target/xbuild/x86_64-unknown-linux-gnu/release/libpubkycore.so
        '
    install_artifact \
        "target/xbuild/x86_64-unknown-linux-gnu/release/libpubkycore.so" \
        "linux-x86-64/libpubkycore.so"
}

build_linux() {
    if [ "$HOST_OS" = "Linux" ]; then build_linux_native; else build_linux_in_container; fi
}

# --- macos ------------------------------------------------------------------

build_macos() {
    if [ "$HOST_OS" != "Darwin" ]; then
        echo "Error: the macOS row has to be built on macOS." >&2
        exit 1
    fi
    if [ "$HOST_ARCH" != "arm64" ]; then
        echo "Error: Apple Silicon only. Intel Macs are not a target — see the header." >&2
        exit 1
    fi
    echo "Building aarch64-apple-darwin natively..."
    rustup target add aarch64-apple-darwin
    cargo build --release --target aarch64-apple-darwin
    install_artifact \
        "target/aarch64-apple-darwin/release/libpubkycore.dylib" \
        "darwin-aarch64/libpubkycore.dylib" \
        strip
}

# --- windows ----------------------------------------------------------------

# Windows on Windows, because there is no cross build worth having: `x86_64-pc-windows-msvc` wants
# the MSVC linker and the Windows SDK, and the `-gnu` target that *can* be cross-built produces a
# DLL against a different C runtime from the one every other Windows consumer links.
#
# Git Bash is what `uname -s` sees on a GitHub `windows-latest` runner, which is why this is one
# recipe in this script rather than a `.ps1` sibling that would drift from it.
build_windows() {
    case "$HOST_OS" in
        MINGW*|MSYS*|CYGWIN*) ;;
        *)
            echo "Error: the Windows row has to be built on Windows (Git Bash, as on a runner)." >&2
            exit 1
            ;;
    esac
    echo "Building x86_64-pc-windows-msvc natively..."
    rustup target add x86_64-pc-windows-msvc

    # **`+crt-static` is load-bearing, not a size tweak.** A Rust MSVC cdylib links the VC runtime
    # dynamically by default, and `vcruntime140.dll` is *not* part of Windows — it arrives with the
    # Visual C++ redistributable. On a machine without it `LoadLibrary` fails, JNA reports
    # "The specified module could not be found", and loopky's classifier reads those two words as a
    # 404: the agent is told the deck it asked for does not exist, on a box that could never read
    # one (loopky#301). A CI runner has the redistributable, so nothing here would notice — which is
    # exactly why the workflow asserts on the import table rather than on the build succeeding.
    RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static" \
        cargo build --release --target x86_64-pc-windows-msvc

    # No `strip`. MSVC keeps debug info in a separate `.pdb` rather than in the image, so there is
    # nothing to remove, and the host `strip` cannot read a PE file anyway. `cargo` also emits
    # `pubkycore.dll.lib`, `.exp` and `.pdb` beside the DLL; only the DLL is a consumer's business.
    install_artifact \
        "target/x86_64-pc-windows-msvc/release/pubkycore.dll" \
        "win32-x86-64/pubkycore.dll"
}

# --- shared -----------------------------------------------------------------

# install_artifact <built path> <path under bindings/desktop> [strip]
#
# `strip` is passed only when the artifact was produced by the host toolchain. A cross build is
# stripped inside the container by the *target's* strip, because the host's cannot read the file.
install_artifact() {
    local src="$1" dest="$OUT_DIR/$2" want_strip="${3:-}"
    if [ ! -f "$src" ]; then
        echo "Error: expected $src to exist after the build." >&2
        exit 1
    fi
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    # Debug symbols are ~40% of the file and no consumer reads them; the Android script strips for
    # the same reason.
    if [ -n "$want_strip" ]; then strip -x "$dest" 2>/dev/null || true; fi
    echo "  -> $dest ($(wc -c <"$dest" | tr -d ' ') bytes)"
}

case "${1:-}" in
    linux) build_linux ;;
    macos) build_macos ;;
    windows) build_windows ;;
    all)
        # Windows is the one row that cannot be produced from anywhere else, so `all` on a Windows
        # host means that row and nothing else — the Linux cross build wants Docker, which is not
        # what a Windows runner is for.
        case "$HOST_OS" in
            MINGW*|MSYS*|CYGWIN*) build_windows ;;
            *)
                build_linux
                if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then build_macos; fi
                ;;
        esac
        ;;
    *) usage; exit 1 ;;
esac

echo "Desktop build finished."
