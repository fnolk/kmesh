#!/bin/sh
set -eu

if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    echo "Set CARGO_TARGET_DIR to a shared build directory before running this script." >&2
    exit 2
fi

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "cargo-zigbuild is required on PATH." >&2
    exit 2
fi

if [ -z "${CARGO_ZIGBUILD_ZIG_PATH:-}" ]; then
    if ! command -v zig >/dev/null 2>&1; then
        echo "zig is required on PATH or via CARGO_ZIGBUILD_ZIG_PATH." >&2
        exit 2
    fi
    CARGO_ZIGBUILD_ZIG_PATH=$(command -v zig)
    export CARGO_ZIGBUILD_ZIG_PATH
fi

if [ -z "${CARGO_ZIGBUILD_CACHE_DIR:-}" ]; then
    CARGO_ZIGBUILD_CACHE_DIR="$CARGO_TARGET_DIR/.kmesh-zigbuild-cache"
    export CARGO_ZIGBUILD_CACHE_DIR
fi

cargo zigbuild --locked --release --target x86_64-unknown-linux-musl
cargo zigbuild --locked --release --target aarch64-unknown-linux-musl
cargo build --locked --release --target x86_64-apple-darwin
cargo build --locked --release --target aarch64-apple-darwin
