# Historical Roc reflection backport

The selected application compiler is the unmodified official November 24
`-safe` release in [the platform pin](../../toolchain.json): upstream's build of
the same commit with Zig's runtime safety checks enabled. Use `xtask bootstrap` to
install it. Linux archives have separate target pins; all three targets use the
matching upstream `vendor/RustGlue.roc` ABI generator.

The separately reviewed formatter remains on September 12. Bootstrap admits the
explicit November 24 compiler / September 12 formatter pair and still verifies
both binary identities and the formatter's source/patch provenance.

This directory preserves an earlier reflection backport for interpreting older
artifacts. The [patch](glue-layouts.patch) applies to Roc commit
`b195f5b23eaecc572659d30acfc4ddea6c9d4ba4` and incorporates the three commits from
[upstream PR 11254](https://github.com/roc-lang/roc/pull/11254).
[Build provenance](build-provenance.json) records exact inputs and the historical
output digest. It is not the current compiler and is not needed to bootstrap a
fresh public checkout.

The backport omitted the inapplicable `GlueProtocolLock.has_payload` test-schema
hunk and adapted a glue release-policy arm to its older surrounding formatting.
Parser, checker, lowering, code generator and formatter implementation files
outside glue were unchanged. Cached build paths were not normalized, so this
record does not claim bit-for-bit reproducibility or current Linux qualification.
See [verification coverage](../../docs/VERIFICATION-COVERAGE.md) for current gates.
