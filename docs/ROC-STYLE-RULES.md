# Roc Style Rules

Status: associated-definition spacing and a 120-column width are implemented in
the native formatter patch. Definition-before-reference remains a proposal.
Apple Silicon app compilation uses the separately reviewed
[reflection backport](../tools/roc-compiler/README.md) on Roc
`nightly-2026-09-05-b195f5b`, retaining its language semantics. Platform formatting
uses an independently pinned build of that base source with the patch below.

See [formatter tooling](../tools/roc-formatter/README.md) for installation, tests,
editor invocation and the upstream-ready patch. There is no second parser or
text-rewriting pass.

## Tooling Choice

Roc's formatter is intentionally not configurable, and this pinned compiler has
no public lint-plugin API. A Roc platform's runtime capability surface cannot
install compiler diagnostics or formatting rules.

Maintain a small, reviewed patch set against the pinned upstream compiler rather
than write a second Roc parser or infer bindings from source text. The spacing
patch is installed independently so it does not replace the app compiler during
ongoing spike work. A future semantic rule must also reach compilation/admission;
a formatter-only binary cannot enforce it. Propose the broadly useful spacing
change upstream; do not depend on upstream accepting either rule.

An external tool built against the compiler's exact internals is possible, but
would still depend on unstable compiler structures. It is not an ordinary plugin
and would require additional integration to keep editor and build results equal.

## Rule 1: Definition Before Reference

Proposed diagnostic: `day2.definition-before-reference`.

Require references to named, function-valued definitions in the same source module
to appear after the implementation. This includes references passed as callbacks,
not just calls. A signature above a use does not make an implementation below that
use count as already defined. Check module helpers and associated methods alike.

Allow direct self-recursion inside the current definition. Reject forward sibling
references, which also rejects mutually recursive groups. Exempt imports from the
line-order comparison: two different files have no meaningful textual order.
Keep Roc's existing local use-before-definition diagnostics.

```roc
# Rejected even though complete is passed as a value, not called here.
analyze = register_command(complete)

complete : Input -> Output
complete = |input| transform(input)
```

The fix is to move the complete signature-and-implementation group before analyze.
The example is schematic; `register_command` is not a new SDK capability.

### Implementation

1. Build a source declaration table, including implementation spans, scopes and
   matching annotations. `src/parse/DeclIndex.zig` already has scope, declaration
   kind, paired annotation/declaration, and source-region information. Identify
   callable values using checked types, not just lambda-shaped syntax: a function
   can also be an alias or the result of another expression.
2. Retain declaration identities through canonicalization and type checking.
   Look up the actual binder referenced by each expression, including callback
   values and references in unused branches. A local parameter sharing a name
   with a module function must not be mistaken for that function.
3. Use checked dispatch targets for receiver calls such as `value.transform()`.
   Ordinary record fields and similarly named methods on unrelated types are not
   interchangeable. Run the final comparison after dispatch resolution, before
   accepting a clean checked artifact.
4. For a reference with a same-module named target, compare its source position
   with the target implementation's end, with the explicit self-recursion
   exception above. Report the use and definition locations and the rule ID.
5. Do not automatically reorder definitions initially. Moving complete groups,
   comments, and interdependent values is a separate code-action problem.

This is a **source-reference ordering rule**, not a claim that every eventual
runtime callee occurs earlier in a file. Higher-order parameters and generic
evidence-dependent dispatch may not denote one concrete local declaration at the
source reference. They are not converted to guessed targets or silently treated
as proofs about runtime call order. A stronger restriction would require checking
specialization evidence or rejecting those forms, with a different compatibility
cost and an explicit policy decision.

The current `checked-types.json` cannot supply this analysis: `SchemaGlue.roc`
exports type shapes, not all resolved source-reference identities. The existing
LSP symbol list is not a substitute for compiler binding analysis either.

## Rule 2: Blank Lines Between Definitions

Implemented formatting policy: blank lines between associated definition groups.
This is formatter behavior, not a new compiler diagnostic or configurable lint ID.

Insert an empty line between definition groups inside `Type :: ... .{ ... }`.
Do not insert one between a matching signature and its implementation. Preserve
comments with the definition they document; do not separate an inline comment
from the preceding expression. Handle nested blocks and methods without
signatures using the parser, not line matching. This deliberately reuses native
top-level spacing semantics, including preservation of an existing intra-pair
blank line; it does not introduce a new maximum-spacing rule.

The formatter already groups top-level definitions using `DefInfo` and
`isPairedAnnoDecl`. The patch reuses that grouping in its associated-statement loop, using
the comment-aware separator mechanism (`flushCommentsBeforeMin`). This changes
whitespace policy, not Roc syntax or the application's HTML authoring model.

The patched `roc-fmt-day2 fmt` fixes the spacing, and `fmt --check` rejects the
compact form. `xtask fmt` / `fmt-check` verify the binary and patch digests before
invoking it. The unpatched `.toolchains/roc fmt` does not enforce this policy.
Formatting an already formatted file produces identical bytes. Comment-only
associated blocks now retain their comments instead of silently dropping them.

## Rule 3: 120 Columns

Wrap code at 120 columns, including indentation. Tabs use four-column tab stops;
Unicode code points count as one column. Preserve literal and comment content:
strings, URLs, comments and identifiers may remain longer when they cannot be
split safely. There is no configurable width or formatter escape directive.

The native formatter measures buffered output and expands explicit AST syntax
groups at legal boundaries. It retains existing expanded layouts and method
spacing. Regression tests check the 120/121 boundary, nested syntax, unchanged
parse trees, preserved content and identical output on repeated formatting.
`fmt --check` rejects code that needs wrapping, through the same pinned tool used
by `xtask fmt` and `fmt-check`.

## Enforcement And Delivery

Current delivery separates source-built candidates from installation of reviewed,
binary-pinned releases, and covers `xtask` formatting and platform
verification. Editor use is explicit configuration. Per-app isolated CI/admission
does not yet run this formatter. The following remains the broader plan for
mandatory semantic-rule delivery, not a claim that these gates already exist:

1. Pin the upstream source commit, patch-set digest, build-toolchain inputs and
   resulting compiler binary. Build the compiler patch through reviewed platform
   tooling; app developers cannot supply plugins, compiler flags or rule toggles.
2. Run formatting checks and the semantic diagnostic against the exact authored
   source snapshot before accepting a build. Apply the same rules to authored
   SDK and fixture code. Exempt only host-proven generated or vendored inputs,
   not arbitrary app directories named `generated` or `vendor`.
3. Include the rule implementation and configuration in build evidence and cache
   identity. Old clean compiler results must not bypass new lint rules. Either
   invalidate them or recheck the admitted bytes under the current pinned rules.
4. Use the same patched tool in `xtask fmt`, `fmt-check`, build admission, and the
   editor. Editor diagnostics are convenience; platform-owned build failure is
   enforcement. Exercise direct and isolated builds so an alternate entrypoint
   cannot bypass the checks.
5. Update authored examples and reviewed SDK pins deliberately. Source whitespace
   changes still affect artifact and sealed-interface hashes. Do not rewrite
   existing company instance bindings or reinterpret historical evidence.

## Acceptance Tests

Ordering tests need earlier/later module functions and associated methods,
qualified and receiver syntax, callbacks, aliases, shadowed parameters, nested
scopes, earlier signatures with later bodies, self-recursion, mutual recursion,
unused branches, imports, and generic-dispatch cases. Include passing controls
and assert the intended rule ID and both source locations, not any compile error.

Formatting tests need compact and already separated methods, omitted signatures,
matching and mismatched annotations, constants and nested types, empty associated
blocks, leading/trailing/inline comments, and mixed newline input. Check golden
output, parser equivalence, idempotence, and `--check` success/failure behavior.

Pipeline tests must cover changed rule versions, stale caches, modified source
after checking, forged generated-source exemptions, editor/CLI agreement, and the
existing native app and adversarial acceptance fixtures.

Spacing is delivered first. Next would be the resolved-reference diagnostic and
the mandatory per-app pipeline gates, with their complete acceptance suites.
Keep implementation status separate from that future policy.

## Compiler Sources

The investigation used upstream commit
`b195f5b23eaecc572659d30acfc4ddea6c9d4ba4`, also available in the local pinned
source archive under `.research/`.

- [Roc's formatter policy](https://www.roc-lang.org/friendly): intentionally no style configuration.
- [Formatter grouping and associated blocks](https://github.com/roc-lang/roc/blob/b195f5b23eaecc572659d30acfc4ddea6c9d4ba4/src/fmt/fmt.zig): top-level grouping near lines 515-589, associated formatting near 799-818, comment-aware spacing near 3651.
- [Declaration index](https://github.com/roc-lang/roc/blob/b195f5b23eaecc572659d30acfc4ddea6c9d4ba4/src/parse/DeclIndex.zig): scope, source region and paired annotation information.
- [Canonicalization](https://github.com/roc-lang/roc/blob/b195f5b23eaecc572659d30acfc4ddea6c9d4ba4/src/canonicalize/Can.zig): scope restoration and forward-reference identities.
- [Checked artifacts](https://github.com/roc-lang/roc/blob/b195f5b23eaecc572659d30acfc4ddea6c9d4ba4/src/check/checked_artifact.zig): resolved references and late dispatch checking.
- [Dispatch registry](https://github.com/roc-lang/roc/blob/b195f5b23eaecc572659d30acfc4ddea6c9d4ba4/src/check/static_dispatch_registry.zig): concrete targets and evidence-dependent dispatch.
