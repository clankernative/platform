# Diagnosing native glue crashes

A historical cold-cache compiler failure produced SIGSEGV from `roc glue` for
invalid nominal types that `roc check` diagnosed normally. This was observed with
September 12 and September 19, 2026 nightlies; it does not establish the status of
later upstream releases. The original application reduction is private.

When investigating a glue crash, run `roc check` against the same staged platform
root and repair reported application type errors first. Preserve a fresh private
compiler cache when comparing check and glue paths: a warmed cache can mask the
failure. A no-op glue specification can help distinguish compiler lowering from
the platform's schema-reflection code. Reduce the input to synthetic source before
filing a public upstream report; never attach company app artifacts or caches.
