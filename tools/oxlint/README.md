# Pinned JavaScript linter

`day2 ci check` lints every regular `.js`, `.mjs` and `.cjs` file of an app
repository with the official oxlint 1.80.0 release binary (no Node or npm) and
the one platform configuration in `oxlintrc.json`. Apps cannot add or override
configuration: `--config` names this file, nested configs are disabled and
ignore files are not read. Unused `eslint-disable`/`oxlint-disable` directives
are errors. oxlint never reads a file whose name contains `.min.`, `-min.` or
`_min.`, even with `--no-ignore`, so `day2 ci check` refuses such names before
linting: an app commits the source it builds, not minified output.

`darwin-arm64.json` and `linux-x86_64.json` pin each host's release archive and
the one binary it holds by URL, sha256 and size. `xtask bootstrap-oxlint`
downloads the archive, verifies it, extracts only that binary, verifies it and
installs it as `../.toolchains/oxlint`, beside the Roc toolchain; the SDK
tooling image runs it at build time. Every lint run verifies the installed
binary against the pin again and never downloads.

The configuration enables ESLint 10's `recommended` rules with today's options
(`no-empty` allows an empty catch, `no-constant-condition` allows `while
(true)`, `no-unused-vars` ignores arguments, caught errors, rest siblings and
`_`-prefixed names), with ES builtin, browser, Node and `chrome` globals. oxlint
1.80.0 implements 62 of the 64 rules: `no-dupe-args` and `no-octal` have no
oxlint rule. Both are syntax errors in modules; only `.cjs` scripts can reach
them. oxlint does not read `/* global */` comments; declare a host global with
an `eslint-disable-next-line no-undef` comment or read it from `globalThis`.

To move to another oxlint release, replace both pins with the new release's
asset identities (the GitHub release lists each asset's sha256) and the
extracted binaries' sha256 and sizes, then rerun `xtask bootstrap-oxlint`.
