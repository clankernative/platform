# OpenTofu provider inputs in CI

The infrastructure matrix and three provider integration jobs use an isolated
provider cache under each runner's temporary directory. GitHub Actions retains
only those provider packages, keyed by OS, architecture, OpenTofu 1.11.5 and the
configuration's complete committed `.terraform.lock.hcl`. There are no prefix
restore keys. Working directories, state, plans, credentials and test results
are not cached.

Every job still runs the original `init -backend=false -lockfile=readonly`,
`validate` and mocked `test` commands. OpenTofu verifies cached packages against
the lockfile checksums before using them; a cache hit never skips a check.
The lockfile-breaking cache option and development overrides are not enabled.

Provider downloads and registry discovery allow five retries for eligible
connection errors and retryable server responses. Registry metadata requests
have a 30-second timeout; this setting does not bound provider package requests.
The original 20-minute job limit remains. Checksum failures and permanent HTTP
refusals are not retried by a whole-job wrapper.

This reduces repeated release ZIP downloads; registry metadata remains online,
so the cache does not make infrastructure verification fully offline. Expired
or evicted caches are ordinary misses and use the same verified download path.

See the pinned version's [provider cache and checksum rules](https://opentofu.org/docs/v1.11/cli/config/config-file/#provider-plugin-cache)
and [provider retry settings](https://opentofu.org/docs/v1.11/cli/config/environment-variables/#tf_provider_download_retry).
