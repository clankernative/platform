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
available with `cargo test --locked -p xtask formatter_native -- --ignored`.
The public full gate checks the source tree separately.

This build is **not bit-for-bit reproducible**. Mach-O link UUIDs and embedded Zig
cache paths vary. The fixed build root `/tmp/day2-roc-formatter-build` removes
checkout-path variation but does not solve those remaining causes. A rebuilt
candidate requires explicit review and pin promotion before distribution.
Historical local logs are not public release evidence.
