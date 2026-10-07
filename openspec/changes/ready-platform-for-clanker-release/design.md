## Context

See proposal.md. Read-only audit on 2026-10-07 found:
- main: `c4aa7a2a7f0f85f73c795fca815b0d4de3bbdcf5`; four upstream commits absent from the qualified integration.
- local integration: `2d5b52c1d42f46df80008530ce993a339423de67`, common ancestor `5d67b4790e485ded82332dff29f73b9a085f5d5e`.
- #98: `studio-page-contracts`, head `32d410055c53cf179b7c585d16f4c11d7ec3fd80`, targets main, currently conflicted.
- #126: `feat/app-contract-export`, head `145dd8eccf31a2ad510cfc3c4b4b16446f3141d0`, stacked on #98.
- #98 fixture cleanup `32d4100` and local `5a0c64c` have identical stable patch ID `8b75be0ed5d078c3782590435e4e49dfb8beaf24`.
- #126 export `145dd8e` and local `556e0d1` have identical stable patch ID `acb78ee7b3e3aa468f2561b8042a6709608ac81f`.
- Overlaps with upstream: AGENTS.md, architecture-rules.json, web.rs, web_live.rs, build_native.rs and xtask main.rs.
- app-create's closed manifest parser rejects the released mandatory `legal` field.

## Goals / Non-Goals

**Goals:** A latest-main-based reviewable integration, strict released-bundle authoring, unchanged catalog/app domain authority, and truthful final-source verification.

**Non-Goals:** Blindly merging stale PRs; compatibility/migrations; app-side installers or a second SDK; automatically approved execution; downloads during builds; new components/BB/browser acceptance; changing unrelated PRs; production deployment.

## Decisions

1. Work in an isolated Platform worktree. Preserve original branches/evidence, reconcile equivalent patches once, and review overlaps against both parents rather than accepting either side wholesale. The user explicitly authorized new/edited PRs and closing obsolete related PRs, but prohibited merging. Preserve original branches/evidence; close old PRs only after the replacement exists and its coverage is explicitly linked.
2. Keep logical review boundaries: neutral assembly (#98), generic admitted contracts/status (#126), optional onboarding/release alignment. Retain latest main's effect/schema checks, faster gate implementation and explicit no-legacy policy. Use one fresh current-main PR with explicit logical review sections and focused release-alignment commits, superseding the stale #98/#126 stack rather than introducing parallel duplicate proposals.
3. Treat legal entries as a closed required shape, bounded regular files with reviewed path/count/size/digest checks. Retain them outside the locked package so canonical package identities and generic assembly semantics do not change. No optional old manifest interpretation, relaxed unknown-field rejection, symlink allowance or larger executable budgets.
4. Do not move operations into an app SDK or Rust recipe. Existing Roc chooses/captures/authors/builds/publishes; Rust supplies atomic capture, evidence and enforcement. Keep explicit SDK/automation catalogs and reserved names consistent.
5. Existing Clanker apps retain locks/catalog/source. Operators restore exact released bytes to their declared path and separately approve the compiler; scaffolding authors only normal app-owned UI/lock inputs. Runtime notice redistribution is retained/documented without inferring app domain intent.
6. Prior native gate and release evidence remains valid for its frozen trees, not for a newly reconciled tree. Run xtask fmt/fmt-check, targeted regressions, verify-fast and scoped supported native creation, then ordinary verify on frozen final source. Retain failures; never normalize fixtures/add skips or bypass sealed/compiler/ABI checks.
7. Hosted CI was blocked and explicitly deferred for the release. Do not modify billing or label CI passed. This does not waive Platform's required local full gate. No automatic PR merge, repository visibility change or production rollout.

## Risks / Trade-offs

- Upstream credential/effect changes collide with UI host code → review exact current-main behavior and add/retain security regressions; no broad theirs/ours resolution.
- Duplicate patches and stale PR descriptions obscure the actual diff → compare stable patch IDs, preserve provenance and update reviewed dependency/evidence descriptions.
- Notices enter served/catalog resources accidentally → place them in a separate dependency legal closure and assert catalog hashes/lock entries unchanged.
- Captured approval or obsolete source reuses old evidence → bind capture/build/admission to exact bytes and final source identity; preserve no-clobber and source-revalidation tests.
- Unsupported Linux native tooling/hosted CI blocks qualification → report separately, use reviewed Apple Silicon native tooling; do not port builders or weaken gates.
- New main policy conflicts with old rollout prose → apply the current no-legacy rule directly, preserving GoLinks links; no migration/cutover work.
