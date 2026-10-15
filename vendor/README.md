# Upstream Code

RustGlue.roc originates from src/glue/src/RustGlue.roc in the pinned Roc source
archive nightly-2026-10-13-b17d287. Its license is preserved in ROC-LICENSE (UPL
1.0). The archive checksum and compiler pin are in ../toolchain.json.

Local change: explicit unsafe blocks around generated raw-pointer operations in
unsafe functions, for Rust 2024's unsafe_op_in_unsafe_fn checking. The same four
reviewed allocation/capture-pointer patch hunks are applied to October 13's
upstream generator. No local layout or calling-convention changes were made;
upstream ABI updates are retained verbatim.

RustGlueSep5.roc retains the exact prior September 5 generator, including those
same four Rust 2024 safety hunks. The native compiler catalog selects RustGlue.roc
for official October 13 on every supported target, and RustGlueSep5.roc only for
the reviewed historical macOS backport. Both generator files are included in
platform source fingerprints. Linux target execution is qualified by its own CI
lane; downloading and checking its compiler bytes is not runtime qualification.

crates/worker/generated/roc_platform_abi.rs is regenerated from this file and the
minimal SDK ABI platform on every build. Do not edit generated layouts by hand.
The generator is included in artifact source fingerprints. The generated file
is excluded from authored source identity; the compiled worker archive and
executable are covered by their output hashes.

The upstream Rust platform template was also consulted at commit
977d2babd4e435ea0a7e5647ab68d21323f2217f:
https://github.com/lukewilliamboswell/roc-platform-template-rust

Compiler distribution:
https://github.com/roc-lang/nightlies
