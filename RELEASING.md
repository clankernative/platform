# Releasing

The public source repository is `clankernative/platform`. Company instances and
apps are independent private repositories. Never publish a tarball of the parent
workspace, local state, compiler caches or application artifacts.

1. Update dependencies and notices, then run the full stable-snapshot `xtask verify`
   gate. Run Gitleaks on the final source and history, `cargo audit`, and the
   OpenTofu mocked contract tests. Investigate findings; do not blanket-allow a
   directory or disable a scanner.
2. Run `xtask source-export NEW_DIRECTORY`. Verify that isolated export on a clean
   supported machine using only the documented public bootstrap dependencies.
3. Review the release contents, compatibility/migration notes and licenses. Runtime
   images must contain the platform license, third-party notices and native-library
   copyright files. Scan the final container image's OS packages separately.
4. Publish versioned platform binaries/images with checksums, exact source revision,
   toolchain pins and CI provenance. Company app images and artifacts are private.
5. Protect `main` with reviewed pull requests, required `verify`, `secrets`,
   `dependencies` and `infrastructure` checks, blocked force pushes/deletions and
   stale-review dismissal. Enable private vulnerability reporting, dependency
   alerts, secret scanning and push protection. Require approval for fork workflows;
   never use company self-hosted runners or deployment credentials for untrusted PRs.

The formatter release tag is `roc-formatter-2026-09-12`, with asset
`roc-fmt-day2-aarch64-apple-darwin`. Its SHA-256 must match
[the formatter pin](tools/roc-formatter/toolchain.json). Include the source pin,
both patch files, Roc license and provenance with that release. Bootstrap downloads
the exact reviewed binary and rejects a changed digest. A freshly built candidate
does not automatically become a reviewed release.

While this repository is private, GitHub release assets require repository access.
Download the formatter with `gh release download roc-formatter-2026-09-12 --repo
clankernative/platform --pattern roc-fmt-day2-aarch64-apple-darwin`, then pass that
file to `xtask bootstrap-formatter`. Public anonymous bootstrap becomes available
when the repository and release are made public together.

## GitHub activation at publication

The repository can be staged privately. GitHub Free organization repositories
cannot enforce private-repository branch protections; private vulnerability
reporting is available for public repositories. Do not represent either as active
until the API confirms it. After the owner deliberately makes the repo public:

```console
gh api repos/clankernative/platform/branches/main/protection --method PUT --input .github/branch-protection.json
gh api repos/clankernative/platform/private-vulnerability-reporting --method PUT
gh api repos/clankernative/platform/vulnerability-alerts --method PUT
```

Enable secret scanning and push protection in the repository's Code security
settings and verify them. Keep Actions' default token permissions read-only and
disable Actions approval of pull requests. Require all seven CI check contexts
in the supplied [branch protection payload](.github/branch-protection.json).
The payload includes administrators, requires review of the latest push, resolves
conversations, and disallows force-pushes and branch deletion. Obtain a passing
first public CI run and verify the private advisory URL before announcing release.
