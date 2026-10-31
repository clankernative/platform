# Cold Pod publication during enrollment

The issuer can receive a native task's enrollment packet before Kubernetes has
published that task as a Running container. It may await only a checked, live,
selected Pod in Pending with the selected container's sole state equal to
waiting/ContainerCreating, first attempt, no prior termination and unchanged
configured image, node and any published container/image identity. Missing or
malformed status, unknown or terminal lifecycle and mismatches refuse.

Pending grants nothing. The same retained process/runtime handles and original
five-second acquisition cover each read and bounded kernel wait. Actual actor
checks bracket reads and waits; all Running container, CRI, workload lineage,
Node, parent, signing and publication checks remain required. Errors and expiry
are terminal for this acquisition; there is no renewed enrollment or retry of a
failed native owner. Real kernel conformance tests remain separate.

The uncapped issuer work record is `day2_native_issuer_work_v2`. Its optional
`request_failure_stage` comes from a closed annotation on the actual request
error, never the last-entered phase or formatted foreign error. Null means the
request had no classified error; the existing outcome still distinguishes
request and parent-check failure. Counters and cutpoints retain their existing
meaning and grant no authority.

Native43's historical error remains unknown. A later Running observation makes
a publication race plausible, but does not prove what the issuer read. Focused
response and clock fixtures do not qualify actual Linux enrollment or establish
that this was the cause of a native failure.
