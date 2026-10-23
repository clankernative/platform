# Reviewed formatter provenance

The selected binary is pinned by [toolchain.json](toolchain.json), including the
upstream source archive, Zig distribution and both patches. The patches apply in
order: [spacing and width](associated-method-spacing.patch), then
[integer grouping](integer-digit-grouping.patch). Only upstream `src/fmt/fmt.zig`
is changed. The application compiler remains unmodified.

The selected executable SHA-256 is
`beb452f23cdd099c416e2c05e5e8a20fa9d07a25a86cd33620f7f4765f510c23`.
It is distributed with these inputs in the
[reviewed release](https://github.com/clankernative/platform/releases/tag/roc-formatter-2026-09-12).
Bootstrap checks the exact executable digest; it never promotes a fresh build.

`xtask build-formatter` downloads pinned inputs, applies both patches, runs the
native formatter module tests and builds a candidate with isolated caches.
Its candidate artifact includes build provenance. Native integration checks are
available with `bazel run //crates/xtask:xtask -- test-rust //crates/xtask:unit_xtask formatter_native --ignored`.
The public full gate checks the source tree separately.

This build is **not bit-for-bit reproducible**. Mach-O link UUIDs and embedded Zig
cache paths vary. The fixed build root `/tmp/day2-roc-formatter-build` removes
checkout-path variation but does not solve those remaining causes. A rebuilt
candidate requires explicit review and pin promotion before distribution.
Historical local logs are not public release evidence.


## Linux x86_64

The Linux output is separately pinned by [linux-x86_64.json](linux-x86_64.json).
Its reviewed SHA-256 is
`4b4eed88a6540d041fc33fe5eecdbc43ee8fcfa4a549931bf4369e21fad49825`
(226,687,584 bytes, ELF64 x86_64 with `/lib64/ld-linux-x86-64.so.2`).
The [hosted build](https://github.com/clankernative/platform/actions/runs/38468385595)
at commit `313a32b12c66ec0ee2bdd716b0f09e97c00b44d7` passed 114 native formatter
tests and 22 Rust admission, process-group and resource-monitor guards.
One existing installed-formatter integration case was ignored during this
candidate build; installed formatting and platform qualification are separate.

[The bounded provenance](LINUX-SOURCE-PROVENANCE.json) binds the exact upstream
source commit/archive, both patch hashes, Zig 0.16.0 archive, native baseline CPU,
ReleaseFast/strip/version flags and one-job build. The Linux release contains
these reviewed bytes and provenance; it leaves the macOS release and pin intact.
The native binary build completed in 1,283.6 seconds. Its sampled group RSS peaked
at 8,193,581,056 bytes under the unchanged 8 GiB guard. This is one tool build,
not a CI speedup measurement or a reproducibility guarantee. Application
compilation retains its separate unmodified official compiler and ABI generator.
