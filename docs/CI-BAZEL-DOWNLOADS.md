# Bazel source downloads in CI

Every CI Bazel bootstrap restores `~/.cache/bazel-repo/content_addressable`
before the first Bazel command. The key includes OS, architecture and the exact
`.bazelversion`, `MODULE.bazel`, `MODULE.bazel.lock` and `Cargo.lock`. There are
no prefix restore keys. Both workflow commands and native xtask subprocesses
already select that repository cache root.

Only checksum-addressed source downloads are persisted. Extracted repository
trees, compiler actions and test results are not in this archive. Bazel rehashes
download-cache entries against the requested checksum before copying them into
a repository. The source pins and `--lockfile_mode=error` remain unchanged.

The successful Linux inputs preparation and Mac compatibility steps retain
their source inputs. These run formatting and whole-workspace lint,
which fetch the compiler, formatter and target dependencies. Bootstrap-only
jobs cannot publish a partial archive under the shared immutable key. Eviction
or a new dependency key still requires downloads; a cache is not an offline or
outage-proof guarantee.

Successful preparation retains these public inputs as a separate ZIP for
three days. After the full gate, the existing Linux and Mac action-publication
jobs copy that ZIP from their admitted origin and publish its dependency key.
The same path runs in PR CI and on main, including when main reuses the queue
proof and skips preparation. No new Mac runner is acquired. Transfers are bounded,
retry once, and require the artifact digest to match. Cache transport failures
only lose acceleration and cannot satisfy or skip a verification obligation.

Bazel 9.3's HTTP connector permits twelve attempts for retryable responses,
including 504. Its exponential backoff has a ten-second base cap before the
existing jitter. The separate repository downloader retains five retries for
eligible socket, hostname and truncated-content failures. These are distinct
retry layers, not a twelve-attempt bound for every combined failure sequence.
Existing parent command/job budgets, compiler actions and fresh tests remain.
No URL rewriting, extra mirrors or checksum-free fallback is added. Docker
builds inherit the retry settings; this Actions cache covers the host commands,
not a Docker builder's separate filesystem.

See the pinned [HTTP connector](https://github.com/bazelbuild/bazel/blob/9.3.0/src/main/java/com/google/devtools/build/lib/bazel/repository/downloader/HttpConnector.java),
[download-cache checksum check](https://github.com/bazelbuild/bazel/blob/9.3.0/src/main/java/com/google/devtools/build/lib/bazel/repository/cache/DownloadCache.java)
and [repository retry policy](https://github.com/bazelbuild/bazel/blob/9.3.0/src/main/java/com/google/devtools/build/lib/bazel/repository/downloader/DownloadManager.java).
