# Roc Formatter Patch

This is a patch to Roc's native Zig formatter, not a second parser, lint plugin,
regex pass, or application SDK capability. It wraps code at 120 columns and inserts
a blank line between associated definition groups while keeping matching
annotations and definitions together. It also preserves comments in otherwise-empty
associated blocks.

The width is fixed, including indentation (tabs advance to four-column tab stops;
UTF-8 code points count as one column). Syntax groups expand at legal parser
boundaries: record and variant types, signatures, calls, collections, lambdas,
expressions and access chains. Strings, URLs, comments and identifiers that cannot
be split without changing content may exceed 120 columns. This is not a literal
rewriter or a comment reflow tool.

The complete upstream change, including regression tests, is
[`associated-method-spacing.patch`](associated-method-spacing.patch). It applies
to Roc commit `220fd4709ea8c96e88ad83cdf4447048418f9045`. The only changed upstream
file is `src/fmt/fmt.zig`. The patch retains its original filename for compatibility.
The native formatter's existing `DefInfo`,
`isPairedAnnoDecl`, and comment-aware separators do the work. A pre-existing blank
line inside a signature/body pair retains the upstream behavior; this patch does
not add a separate maximum-spacing rule. Width selection buffers native output,
measures its actual columns and expands explicit syntax groups. Each retry adds
an expansion to a finite set; it never reparses rewritten text or guesses from
source-line lengths. Regression tests check parser equivalence and stable output.

## Install And Use

On this workspace the reviewed formatter is installed. From the platform directory:

```console
bazel run //crates/xtask:xtask -- bootstrap-formatter
bazel run //crates/xtask:xtask -- fmt-reports
bazel run //crates/xtask:xtask -- fmt-check-reports
bazel run //crates/xtask:xtask -- verify-reports
```

`fmt`, `fmt-check` and `verify` cover the public platform, fixtures and
`examples/reports`. No company app checkout is required.

Bootstrap selects the reviewed native binary: Apple Silicon macOS from the
[macOS formatter release](https://github.com/clankernative/platform/releases/tag/roc-formatter-2026-09-12)
or Linux x86_64 from the
[Linux formatter release](https://github.com/clankernative/platform/releases/tag/roc-formatter-linux-2026-09-12).
It verifies the committed SHA-256 before atomic installation. To supply a copy
from an authenticated download or offline mirror:

```console
bazel run //crates/xtask:xtask -- bootstrap-formatter /path/to/reviewed/roc
```

Mismatched installed or supplied bytes are rejected. The formatter supports
Apple Silicon macOS and Linux x86_64. Application compilation on each host keeps
its independently pinned official compiler and ABI generator.

[`toolchain.json`](toolchain.json) and [`linux-x86_64.json`](linux-x86_64.json)
record each native source, both patches, Zig archive, exact build arguments and
reviewed output hash. Build dependencies are locked by
the upstream source archive's Zig package manifest. Roc embeds absolute source,
Zig and cache paths even in a stripped optimized binary. A fresh source build can
therefore differ byte-for-byte without a source change. Source builds are not
silently treated as reviewed binary releases.

Maintainers can run `bazel run //crates/xtask:xtask -- build-formatter`. It downloads
digest-pinned upstream source and Zig 0.16.0 into a private build directory,
checks the source commit and patch, runs the native formatter module tests, then
builds Roc. It emits `artifacts/roc-formatter/<actual-hash>/roc` plus provenance,
but does not install it or update any pin. Downloads and subprocesses are bounded;
caches and Git configuration are isolated. macOS builds require Apple Command Line
Tools (the initial build used macOS SDK 15.2); Linux builds run natively on x86_64
with the fixed Zig distribution. Linux builds use one Zig job, a 12 GiB per-process
address-space ceiling, an 8 GiB sampled process-group RSS ceiling and 4 GiB disk
headroom. Sampling is not kernel process-tree confinement. Review and update the output pin
explicitly before installing and distributing a new candidate.

Installed tools have separate purposes:

- `../.toolchains/roc`: unchanged application compiler, admission and glue.
- `../.toolchains/roc-fmt-day2`: patched native executable used only for formatting.

The paths above are relative to `platform/`, not this README. The formatter keeps
the original compiler version string because native `fmt` also manages Roc header
version pins. Its separate filename, binary hash and patch hash identify the
custom build; `version` alone does not distinguish it. Do not substitute this
binary for the trusted application compiler.

For an editor that supports an external formatting command, use
`/absolute/path/to/.toolchains/roc-fmt-day2 fmt --stdin` and pass
the document on stdin. Use the equivalent absolute path in another checkout.
No editor configuration is changed automatically; the unmodified Roc language
server still has upstream formatting behavior.

## Regression Tests

```console
bazel run //crates/xtask:xtask -- test-rust //crates/xtask:unit_xtask
bazel run //crates/xtask:xtask -- test-rust //crates/xtask:unit_xtask formatter_native --ignored
```

The native patch tests paired and unannotated methods, constants, mismatched
annotations, nested types, local bindings, comments, empty blocks and mixed line
endings. Width regressions cover the original `CommandDef` record, nested calls,
single record arguments, signatures, variants, lambdas, operators, access chains,
interpolation, match alternatives and exports. Boundary tests exercise 120 versus
121 columns, indentation, Unicode and long literal/comment content. Tests check
stable repeated formatting and parser structure before/after, ignoring source
positions. The historical September 12 suite declared 113 tests. The reviewed Linux build
with both committed patches passed all 114 native formatter tests; its complete
source, recipe and hosted receipt are recorded in
[Linux provenance](LINUX-SOURCE-PROVENANCE.json).
The [source provenance](SOURCE-PROVENANCE.md) records the reviewed rebase,
new upstream dependency, native test/build commands and CLI integration outcomes.

The Rust tests reject tampered pins/patches/binaries and symlinked inputs, check
safe installation, and exercise real native `fmt` / `fmt --check`: checks do not
write, compact definitions and overlong code fail, formatting produces the golden layout, a second
format is identical, header pins are retained, and malformed input is rejected.

Platform verification enforces formatting. Individual app CI/build admission does
not yet invoke this formatter, and the definition-order diagnostic remains
unimplemented. This spacing change is not a security or semantic compiler rule.

## Upstreaming And Upgrades

The patch can be applied to a checkout of its recorded upstream commit with
`git apply --check` followed by `git apply`. Run
`zig build run-test-zig-module-fmt -Dcompiler-version=nightly-2026-09-12-220fd47`
there. Upstream's formatted snapshots will also need regeneration when preparing
a PR against their current main; this pinned patch does not update that broad
snapshot corpus. No upstream PR has been submitted.

When upgrading Roc, either remove the patch after verifying equivalent upstream
behavior, or rebase and review it. Update source, patch and binary pins explicitly,
run the full native formatter suite and integration tests, review any SDK byte
changes, and refresh sealed SDK hashes only after reviewing the actual diff.
Do not auto-accept a changed compiler, patch or generated admission pin.
