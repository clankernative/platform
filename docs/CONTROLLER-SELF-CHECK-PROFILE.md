# Controller full-check profiling

The retained native reserve observation on 23 October 2026 recorded eight full
Controller samples taking 5.495024 seconds in total: 686.878 milliseconds per
sample. Dispatch recorded thirteen samples taking 8.749279 seconds: 673.021
milliseconds per sample. These are inclusive operation-48 totals, not hash
measurements. The surrounding native/authentication timings overlap them;
adding or subtracting those aggregates does not produce a leaf profile.

A bootstrap Controller now collects exclusive diagnostic costs inside each
actual full-check body. It still checks authentication, the original file,
the retained peer and the original file again. Collection ends before the
existing final acquisition sample and refusal-gate completion. The same
original deadline pays for all diagnostic work. No observation is reused as
permission, no checks are skipped, and no timeout is changed.

After an action returns and native borrows unwind, its ordinary evidence record
is preceded by a `day2-native-controller-self-check` record. Its format is
`controller_full_check_exclusive_ns_v1`. Selection, Controller incarnation,
step and sequence join it to the following ordinary evidence record. A partial
export may leave a profile without that matching record; it proves no outcome. There are
at most six profile records per Controller transcript, each under 1024 bytes;
the ordinary twelve-record/2048-byte limits are unchanged. Failed export keeps
the existing sticky evidence-export failure behavior.

`profile.samples` counts attempted full-check bodies, including a partially
executed body that refused. Each `profile.rows` entry is `[attempts, exclusive
nanoseconds]`, in this fixed order:

| Index | Category | Work included |
| --- | --- | --- |
| 0 | Other | Full-check body outside the spans below |
| 1 | Executable bytes | Fresh peer executable SHA-256, reads, metadata and chunk clock checks |
| 2 | Self process | Retained self executable FD and fresh proc-path identity checks |
| 3 | Namespace | Fresh self proc/task/namespace observations |
| 4 | Enrollment policy | Fresh selected policy file checks/read and byte interpretation |
| 5 | Peer | Retained packet-sender identity body, excluding executable-byte work; terminal pidfd guards stay in the parent category |
| 6 | Storage profile | Fresh fixed storage-profile file read and JSON decode |
| 7 | Original file | Writable original image comparison and guards, excluding nested spans |
| 8 | Volume | Current volume/provider/physical checks, excluding nested spans |

Nested categories pause their parent: totals partition the observed body rather
than double-count it. Compare their sum with operation 48 to see work outside
the profile (including final return-clock guards). Nanoseconds avoid rounding
each of the many small checks down to zero. Missing, rewound or unrepresentable
diagnostic clocks make all timing buckets for that body inconclusive; counts
remain historical attempts. Counter overflow stays null. None of these values
can repair a native refusal or extend an acquisition.

Collection is synchronous, local to the actual checking thread and contains
only fixed counters. It does not run during an unrelated sample, ordinary
serving or an issuer check. Leaves outside a profiling scope read no diagnostic
clock. A nested root is inconclusive instead of resetting its parent.

Self-executable content is hashed at acquisition, not on every retained self
check. The repeated peer executable hash is a separate path. A measured cost
for a category does not establish that all its cost is removable: metadata,
path, process, namespace, role, policy, original-clock and refusal checks must
remain fresh. Storage-profile cost includes parsing too.

Kernel-integrity qualification is separate. No file is sealed by this change,
and the writable SQLite original must never be sealed. An fs-verity digest is
not the existing whole-file SHA-256; an authenticated artifact-to-verity digest
binding and actual kernel/filesystem/container-layer qualification are required
before it could replace a content read. Replacement, copy-up and remount must
still refuse through the fresh native joins. The retained timings above do not
establish such support or any verity speedup.

For an isolated Linux peer/self leaf measurement, build and run the explicit
ignored fixture through the ordinary checked harness entry point:

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::process::tests::profile_actual_retained_peer_and_self_guards --exact --ignored --nocapture
```

It acquires actual kernel packet handles, self FDs and namespaces and reports
eight checks of the actual harness executable. It grants no enrolled role,
original database or writer. Its executable size and machine/filesystem differ
from the deployed App; these leaf numbers cannot be substituted for the full
native Controller profile. Existing kernel conformance cases are unchanged.
