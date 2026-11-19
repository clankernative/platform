# Qualification VM retirement

`enabled = false` removes this entire root, including its VPC, subnet, router,
Cloud NAT and service account. Do not use it to retire one VM when another VM
uses that infrastructure.

Keep `enabled = true` and set `instance_enabled = false` to remove only the
qualification VM and the two instance-scoped operator grants. The network,
service account, repository permission and project/service-account operator
grants retain their existing addresses and configuration. Instance identity
and SSH outputs become null. The default remains to create the VM when this
optional root is enabled.

The boot disk's existing auto-delete setting determines what its removal does.
Setting `boot_disk_auto_delete = false` in the same plan that removes the VM
does not update an attachment that is no longer configured. To retain an
existing disk:

1. Review a preparation plan with `enabled = true`, `instance_enabled = true`
   and `boot_disk_auto_delete = false`. Require the same VM and boot disk, no
   replacements and no unrelated changes. Apply only with explicit approval.
2. Read the actual VM and disk identities and verify the boot attachment now
   has auto-delete disabled. Do not infer that from the desired configuration.
3. Generate a fresh plan with `instance_enabled = false`. Require deletion of
   only the VM and its two instance-scoped operator grants; preserve the network
   and every other resource. Apply only after approval of that exact plan.
4. Confirm the retained disk still exists and is unattached. Retained storage
   remains billed and is not managed as a separate disk resource by this root;
   its disposition requires a separate ownership/data decision.

Do not replace an IaC-managed VM deletion with an ad-hoc delete, remove a shared
network, or treat a stopped VM as evidence that its data is disposable.
