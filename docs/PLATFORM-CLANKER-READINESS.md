# Platform released-Clanker readiness — 2026-10-07

**Implementation and scoped consumption pass; final readiness is blocked.**
[Draft PR #130](https://github.com/clankernative/platform/pull/130) replaces
#98/#126. They were closed with explicit coverage links under user authorization,
without merging or deleting their branches/evidence. No PR merge is authorized.

## Source and review boundaries

Gate/scoped candidate: `3f3fc84c080ac13472b4e3d65dacdeb6dfafdef0`; tree `de79b6a633179b2f8ab577e79228a0028d274c28`.
Base main: `c4aa7a2a7f0f85f73c795fca815b0d4de3bbdcf5`. Later documentation/task-status commits are not a new
full-gate result. A successful ordinary final-source `xtask verify` remains required.

Review sections retain each equivalent patch once:
- #98: generic locked preprocessing, bounded captured inputs, strict protocol,
  independent host binding ABI and ordinary admission.
- #126: admitted typed contract export and private artifact/digest-bound local-dev
  status, with hardlink-safe atomic replacement and absent-target no-clobber.
- Optional Roc AppCreate recipe and published-bundle legal alignment.

Current-main authority/credential/effect/private-schema checks, terminal
revocation/conflict retry, faster verification and no-legacy policy remain.
The image-refresh notice uses bounded canonical Maud markup and normal escaping.
Seventeen newly detected filesystem sites were explicitly reviewed, not broadly
exempted. The scaffold digest charges its entry budget before collecting entries.
No architecture checker relaxation or compiler/formatter pin change was made.

Required legal capture is closed and ordered: `legal/LICENSE`,
`legal/NOTICES.txt`, each nonempty, at most 1 MiB and exact digest/length.
Missing/unknown/reordered/unsafe/oversized/tampered/symlinked inputs fail closed;
the unreleased no-legal shape is rejected. Notices are retained under
`.ui-dependencies/legal/`, outside served UI and catalog inputs.
See [APP-CREATE.md](APP-CREATE.md) for operator installation/approval.

## Passed evidence

Linux exact-source checks:
- Architecture: 369 sources, 1628 reviewed effect sites / 1700 occurrences;
  three strict kernel crates, ten package boundaries, seven authority handles.
- Capture: 12 tests, including 13 legal mutations, symlinks, legal/catalog
  separation, no-clobber/source guards and the wide-directory budget regression.
- Live transport: 13 tests. Export: nine tests.
- Assembly: 29 ordinary tests plus the explicitly executed external-provider
  conformance case, using the anonymously restored actual released Linux CLI.
- Independent ABI v2 corpus: all 99 reviewed vectors checked.
- Rust formatting, strict OpenSpec validation and diff checks.

Apple Silicon using reviewed Rust 1.98.1, official unmodified pinned Roc and its
reviewed ABI generator, pinned formatter, isolated OpenTofu 1.11.5 and
Temporal 1.6.1:
- `xtask fmt-check`: exit 0, 222 s; 334 authored Roc files; no source changes.
- Focused capture/recipe/live/export/binding checks: 12 / 3 / 13 / 9 / 12 passed.
- Ordinary `xtask verify-fast`: exit 0, 252 s.
- Recovered ordinary workflows/CLI build: exit 0, 114 s / 81 s.
- Real pinned infrastructure plan smoke: exit 0, 4 s; `applied=false`.

Independent bounded static review found no actionable regressions in its reviewed
boundaries. That was static review, not independent runtime qualification.

## Actual released-bundle creation/admission

The ordinary CLI recipe created all three fresh apps and admitted their artifacts:

| Variant | Exit / seconds | Artifact |
| --- | --- | --- |
| No UI | 0 / 16 | `ef319f60279e1df1442270ab35181d17bd1c07f6f4f142e0d7392c9c0c84049a` |
| HTML | 0 / 17 | `d2aa24238c42fd405459a9a920f5f3233b3e184a44b3d8903d271c2798e6c621` |
| Clanker | 0 / 18 | `0a20789141fb52bf44b373d28a08311790b66ab8c4a7c9ce67443e19c7ceae04` |

Each receipt has `verification_complete=true`, **2 generated cases**, five
required checks and no failure. This is the ordinary build's actual bounded
campaign, **not a 32-case or cache-free claim**.

Clanker inputs came from the anonymously restored published Mac installation:
- Installed manifest SHA-256:
  `d4c62e91187e5d642d4340e6a0e6446dcea43a95884e5e7e289d8bea40c89bd9`.
- Separately reviewed operator pin SHA-256:
  `b5899fa8dbbcde95302bf9fbecb11cf9f975ba5bf4f8372bd0053ac1facd4cd9`.
- Released executable SHA-256:
  `c1b637cd06ce5a93ecd6420878aa7aafaab75a4583f56260c1db18b1672d86f8`.
- Complete package directory is byte-equal: 448 inputs, unchanged
  `sha256:9185573e72c1a2faffec1b038859b052b15954fa984305d5446d905537d31358`.
- Both retained legal files exactly equal release bytes; neither enters the
  vanilla catalog or admitted web resources.
- Future operator pin is durable in the installed bundle, not a staged pin.
  App locks grant no execution/download authority or app-domain rights.

## Retained failures and blocker

- Original red tests reproduced rejection of the released legal field and
  acceptance of missing legal metadata. Intermediate architecture failures were
  resolved through supported markup/import syntax and exact-site review.
- Linux `xtask fmt` and ordinary `verify-fast` failed because pinned native tool
  paths were unavailable. They are not passes or Linux Native qualification.
- The first Mac CLI build failed: externally configured `CARGO_TARGET_DIR`
  conflicted with the existing capability's fixed local `target/debug` paths.
  Environment-only recovery independently COW-cloned relevant Cargo cache
  subtrees (3 s, about 6 MiB disk delta). Example bytes matched with different
  inodes; no destination links; runner/strict-clippy/source hashes unchanged.
  Normal Cargo/workflow checks and CLI build then passed. No manual binary
  substitution, source workaround or admission bypass.
- A hyphenated caller namespace was correctly rejected (exit 2), leaving
  destinations absent. Only the caller names were corrected to underscores.
- **Ordinary full `verify` did not pass.** It ran from
  2026-10-07 20:37:16 to 20:47:58 UTC, recorded 641 s, and exited **143** when
  free space crossed the task's **8 GiB safety floor**. Twenty native fixture
  admissions completed before interruption; no source failure was diagnosed.
  Only the exact task-owned process group was stopped and confirmed empty.
  No cleanup, retry, lowered floor, skip, normalized fixture or guard change.
- Hosted Platform CI run **37677625514** did not execute verification,
  dependencies or secrets jobs. Annotations explicitly cite account
  billing/spending restrictions. No hosted pass, billing change or CI replacement.

## Evidence and continuation

Mac proof root:
`/private/tmp/platform-release-final.EJF53c/recovery.O9kWf4`.
Sanitized `final-receipt.safe.json` SHA-256:
`b9b415938f132d359a06ec6c041e8a02266aa81f82159cdfd1ae99676a94135c`.
Separate `scoped-admissions.safe.json`, retained controller/log/exit/time files,
and candidate-only capacity inventory remain private.
Linux logs/review: `/tmp/platform-ready-logs/`.

Original GoLinks 59364, watched consumer 57663, Studio process 23943, persisted
links, databases, worktrees and evidence were preserved. No new local-dev/browser
campaign, deployment, public release change, global tool replacement or BB work.

Before promoting the draft: recover capacity through an explicitly approved,
task-owned cache cleanup or operator-provided space, preserve all artifacts/logs,
and rerun ordinary full verification on a frozen final source. Do not treat the
partial gate, old-tree gates or released-byte producer checks as substitutes.
Linux release remains CLI-only (glibc 2.39+); this is not production readiness,
hostile-code containment or full browser/Studio acceptance.
