## Context

The existing native-bundle/native-release/restore boundary already provides canonical package closure, hash-first bounded extraction, relocation and no-clobber. The missing first-install step is that restore currently requires a Clanker CLI. GitHub reports clankernative/clanker-ui private, no release, and no project license. The user authorizes public early access and explicitly approved MIT. Source/history/public-surface and third-party notice review is bounded, not a certified legal or secret-free audit.

## Goals / Non-Goals

**Goals:** Obtain CLI 0.1.0 and vanilla 0.7.0 without a Clanker checkout; prove installed bytes in real consumers; publish only qualified bytes and reviewed public source.

**Non-Goals:** BB installation/distribution, Studio UX redesign, extra components, full GoLinks browser acceptance, production-readiness claims, Linux Native isolated-builder work, Windows, a registry, compatibility schemas or global tooling replacement.

## Decisions

- Reuse GitHub Releases and exact existing URL convention; no new registry or latest resolver.
- Add an independently hash-identified standalone CLI asset from the exact same validated archive snapshot. The operator verifies/approves it before first execution, then uses existing safe restore. Reject install-script alternatives. Downloads do not themselves grant execution authority.
- Prioritize macOS aarch64 for full Native/Studio consumption. Linux x86_64 CLI assets require their own package tests; do not imply full Linux Native support.
- Keep existing vanilla version/bytes and app lock schema. Installation lives outside served ui/. Producer/source provenance and executable approval remain explicit.
- One focused Clanker release worktree; reuse the reviewed Mac control session for qualification after source freeze. No seven-worker fan-out. Original checkouts/apps stay untouched.
- Publication is coordinator-owned. MIT and retained third-party notices are approved. Reviewed source may be pushed privately for Mac qualification; repository visibility and release publication remain gated on local consumer qualification. Hosted GitHub CI could not start because of billing/spending limits; the user explicitly deferred that check and reconfirmed publication after local qualification. Retain that failure as a disclosed limitation, without changing billing or claiming hosted CI passed.

## Risks / Trade-offs

- Private-to-public exposes history/issues, not merely release assets → review reachable history, screenshots, metadata and repository surfaces before changing visibility; stop on sensitive material.
- Downloaded bootstrap could be mistaken for trust → provide exact source/target/hash review guidance; keep separate host execution approval and immutable pins.
- Legal ambiguity → obtain MIT approval and retain separate asset/dependency notices before distributing.
- Existing local success could be mislabeled hosted availability → keep local-candidate, hosted-acquisition and consumer-admission evidence separate.

## Migration Plan

Prepare and test candidates locally, freeze exact source, build target assets, qualify clean consumers, then publish reviewed source/tag/assets. Verify anonymous downloads against reviewed hashes and repeat clean consumer acquisition. Never replace an existing release asset silently; withdraw/replace through a new explicit version if identity fails.
