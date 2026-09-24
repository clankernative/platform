# Public resource integration inventory

Instance owners select resources and grants; app code declares typed capabilities.
No company integration inventory is part of this repository.

| Capability | Public implementation and scope |
| --- | --- |
| File metadata and reads | [SDK capability guide](SDK-CAPABILITIES.md); bounded admitted resources |
| Notifications | [command runtime](COMMAND-RUNTIME.md); synthetic local mailbox |
| Directory, Linear and operator alerts | [provider contracts](PEOPLE-PROVIDERS.md); synthetic adapters, live credentials supplied privately |
| Delegation and resource policy | [authority](RESOURCE-AUTHORITY.md) and [enforcement](RESOURCE-ENFORCEMENT.md) |

A declared contract does not imply that a live provider adapter is implemented.
Keep resource names, account identifiers, grants, secrets and operational evidence
in the instance repository. Public tests use synthetic resources only.
