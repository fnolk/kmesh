# Release build validation

`scripts/build-release.sh` builds the Linux musl and macOS release binaries. It requires `cargo-zigbuild`, Zig, and all four Rust targets. Set `CARGO_TARGET_DIR` before running it; set `CARGO_ZIGBUILD_ZIG_PATH` when Zig lives outside `PATH`.

```sh
export CARGO_TARGET_DIR=/path/to/shared/cargo-target
export CARGO_ZIGBUILD_ZIG_PATH=/path/to/zig
export PATH=/path/to/cargo-zigbuild-directory:$PATH
scripts/build-release.sh
```

Linux artifacts should be ELF executables with no `INTERP` program header and no `NEEDED` dynamic dependencies. Verify both architectures with `file`, `readelf -l`, and `readelf -d`:

```sh
file "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh"
readelf -l "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh" | rg INTERP
readelf -d "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kmesh" | rg NEEDED
file "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh"
readelf -l "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh" | rg INTERP
readelf -d "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/kmesh" | rg NEEDED
```

For the static checks, the `readelf` commands should produce no matching lines. macOS artifacts should report their requested architecture in `file` or `lipo -info`:

```sh
file "$CARGO_TARGET_DIR/x86_64-apple-darwin/release/kmesh"
file "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/kmesh"
```

Check the resolved dependency graph for each release target to confirm no OpenSSL or native-tls backend is active:

```sh
cargo tree --target x86_64-unknown-linux-musl -i openssl-sys
cargo tree --target aarch64-unknown-linux-musl -i openssl-sys
```

Cargo should report that `openssl-sys` is absent for both target graphs.
