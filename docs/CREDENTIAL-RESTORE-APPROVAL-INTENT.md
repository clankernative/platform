# Restore challenge intent and final approval time

The preapproval challenge commits to the server's complete `ApprovalIntent`:
grant identifier, full archive digest, target, security epoch, desired executor
identity and existing custody binding. Its domain differs from the final
signed `ApprovalRequest` commitment. The registry-key binding separately binds
the selected approver. A complete intent is compared before verification;
changing any field refuses the ceremony and its actual reader.

The intent has no approval or expiry timestamp. It cannot begin an hour of
approval validity while the person is still considering the challenge. After
genuine passkey completion, durable one-use handling and the qualified clock
floor, the producer must freeze the actual completion time and add exactly one
hour. `request_data` is pure DATA assembly, not that clock or an authorization
constructor. The existing final signed request schema stays unchanged.

The Controller ceremony retains the full intent and delegates to the existing
actual-reader registry verifier. Its digest-only helpers are private to that
module. The ceremony holds no App loan across human interaction. The owning
producer must close and settle the short read action before challenge delivery.

The desired executor email is compared with the actual reader's selected
current-admin email, and the full desired subject is committed to the challenge.
This does not authenticate the executor: the eventual accepting source must
check the actual caller's identity and subject independently. Workload identity
DATA remains supported by the canonical request; this change does not require
all executors to use a human passkey.

Durable challenge/counter completion, clock-floor ownership, signing and
publication, executor authentication and the consuming Fenced continuation are
still producer integration work. No signed grant or native qualification is
provided by these binding types and source controls.
