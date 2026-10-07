## 1. History and scope

- [x] 1.1 Inspect current #98/#126, latest main, patch equivalence and release-schema gap; document ownership and excluded work.
- [x] 1.2 Prepare an isolated latest-main reconciliation and logical review layout, preserving four upstream changes and applying each equivalent integration patch once (fresh branch on c4aa7a2; two conflict areas reviewed; old heads retained, fresh consolidated PR authorized).

## 2. Released bundle alignment

- [x] 2.1 Test and implement mandatory bounded legal capture/retention in existing optional authoring capabilities; reject old/unknown/tampered shapes without relaxing guards or changing catalog bytes (red failures retained; 12 capture tests pass including 13 legal mutations, links and bounded wide-directory scan).
- [x] 2.2 Align exact-release installation/scaffolding docs and test no-UI/plain-HTML behavior, operator approval, dependency paths and legal retention; keep app domain code/SDKs unchanged (3 recipe tests and all 3 real creation/admission variants passed; legal and 448 catalog inputs byte-equal to the anonymous release).

## 3. Verification

- [x] 3.1 Run xtask fmt/fmt-check, focused regressions and ordinary verify-fast while iterating; preserve all failures (Mac pinned fmt-check: 334 files, exit 0; focused regressions and ordinary verify-fast exit 0, 252 s; Linux missing-native-tool failures retained).
- [ ] 3.2 On reviewed Apple Silicon tooling, run scoped creation/admission against the actual published release, then ordinary verify on frozen final source; record precise source/tool identities and limitations. Scoped creation/admission passed on 3f3fc84/de79b6a (2 generated cases and 5 required checks per app); full verify interrupted by the 8 GiB disk safety floor, exit 143 after 641 s, not a pass. Preserve evidence; resume only after safe capacity recovery and ordinary full rerun.

## 4. Review delivery

- [x] 4.1 Prepare/update the agreed nonduplicated PR layout and truthful dependency/evidence descriptions (draft #130 replaces #98/#126, closed with explicit coverage links under user authorization; original heads/evidence preserved; no merge, force-push or visibility change). Hosted Platform CI did not start because of billing; local full gate remains incomplete and draft status is retained.
