# Local credential cost fixtures

These explicit ignored Linux fixtures measure production leaf functions on owned
test inputs. They create no enrolled role, volume, first holder or writer. Their
numbers cannot be summed into the full native Controller sample or substituted
for a new instrumented run on the actual deployment.

Run through the ordinary checked harness entry point, in an isolated Linux
fixture. The policy test requires root-owned temporary files; it never writes
the host's `/etc` policy.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::birth::tests::profile_guarded_policy_cold_and_exact_byte_reads --exact --ignored --nocapture
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::storage_authority::preparation::continuity::retained_initial_read_tests::profile_synthetic_retained_initial_byte_loop --exact --ignored --nocapture
```

The policy fixture calls the actual fresh NOFOLLOW/open, root/mode/size, bounded
read, interpretation and original-clock guards. It verifies eight cold decodes
and zero additional decodes for eight exact-byte hits after a real warmup read.
It reports the generated policy's actual size and a second case padded only with
JSON whitespace to the existing policy byte limit. Padding does not model a
more complex policy. Both measured cases include fresh file reads on every hit.

The original-byte fixture calls the actual allocation/pread/comparison loop on
synthetic owned bytes at one chunk minus/plus seventeen bytes and the maximum
admitted image size. Its callback checks the actual original clock and retained
FD metadata before/after every read and once at completion; expected callback
counts are asserted. It excludes the native volume, directory/path, process,
namespace, role and provider checks that the real caller supplies. It is not a
measurement of the complete writable-original guard. No canary database or disk
is opened, copied or sealed.

Both fixtures use eight bounded repetitions on the same original five-second
clock per input case, including diagnostic work. Missing, reversed or overflowing
diagnostic clocks leave the total null; native errors still fail the fixture.
Setup precedes timing and reads may be warm in the page cache. Nanosecond totals
describe elapsed time on that machine and configuration, including scheduling
and I/O. They establish no CPU-only cost, deployment support, timing margin or
removable work. Existing production checks, refusal behavior and limits do not
change.
