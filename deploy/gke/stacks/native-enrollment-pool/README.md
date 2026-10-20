# Dedicated native enrollment node pool

This root creates one node pool in an **existing zonal GKE Standard cluster**. It
does not manage the cluster, shared node pool, node IAM, KMS keys or any app data.
No native enrollment or runtime qualification is established by creating the
pool. The instance operator approves the trust profile and spend before apply;
supplier readiness and actual capacity must be checked before moving workloads.

The instance supplies the project, zone, cluster, pool/profile names, existing
node service account, machine type and pod PID bound. Keep its backend and
variable files in the instance repository, outside automatic apply workflows.

## Placement

The pool has one Ubuntu/containerd x86 node and no autoscaling. Its taint is
`day2.dev/native-enrollment=<profile>:NoSchedule`. Node replacement uses no surge
node and intentionally interrupts the disposable single-node installation.
Repair and upgrades remain enabled; the new boot must acquire fresh enrollment.

Pass output `placement` to `native_enrollment_placement` on the selected
`day2-app` and `security-shell` roots. They enable hostPID, select this pool and
its protected `day2.dev.node-restriction.kubernetes.io/enrollment` label, and
tolerate only its exact profile taint. They mount only the existing issuer
socket directory `/run/day2-native-enrollment`, read-only. They receive neither
the containerd socket nor a root private key. An unset placement leaves normal
workloads isolated. Apply-time hostPID/socket policy admission must be checked
for the selected namespaces; this root changes no shared admission policy.

The trusted provisioner runs `/usr/local/bin/day2-native-enrollment` with no
arguments and owns its issuer child. Its required root-owned selection is
`/etc/day2/native-enrollment.json`. The issuer needs the fixed runtime socket,
native process-observation permissions and bound Kubernetes API projections.
Issuer/provisioner deployment and the epoch controller are owned by their
supplier implementations; they must use this same placement. Ordinary placement
does not create those processes or qualify their privileges.

All native participants must prove the same actual node boot and initial
PID/user/time domain. hostPID, zero clock offsets, labels, placement and a KMS
signature are insufficient substitutes. Qualify the real kernel sender pidfds,
procfs/nsfs, code/container/runtime joins, clock, namespace and observation
permissions before using a production role. Privileged node agents, init
containers, launchers, debug/ptrace users and node administrators belong to the
trusted computing base; this is not protection from a hostile node root.

## Smallest supported capacity and indicative monthly cost

For the single Calendar canary, the proposed requests are:

| Participant | CPU | Memory |
| --- | ---: | ---: |
| App (current profile) | 1,000m | 512 MiB |
| Shell (current profile) | 500m | 512 MiB |
| Provisioner and issuer (proposed combined allowance) | 1,000m | 512 MiB |
| Epoch controller (proposed allowance) | 250m | 256 MiB |
| **Native total** | **2,750m** | **1,792 MiB** |

`e2-highcpu-4` supplies four vCPUs and 4 GiB. Using GKE's published reservations
leaves approximately 3,920m CPU and 2,972 MiB memory for Pods before system
DaemonSets; allowing 500m/512 MiB for those leaves modest headroom. Two-core
E2 sizes cannot fit the declared CPU requests. This is the smallest supported
predefined E2 size for these budgets, **not a measured native-capacity pass**.
Reconcile actual supplier requests and system Pods before moving workloads; select
`e2-standard-4` if memory needs more headroom. [GKE node reservations](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/plan-node-sizes).

The approved Calendar node's actual allocatable memory was 2,793 MiB, with
approximately 930 MiB of system Pod requests. The proposed native requests leave
only about 71 MiB of scheduling headroom. This is tighter than the initial
allowance above; reconcile actual native requests and measured usage before
workload deployment. A larger machine needs its own cost approval.

At 730 hours/month, on-demand Iowa pricing checked 19 October 2026:

| Item | Calculation | USD/month |
| --- | --- | ---: |
| e2-highcpu-4 | 730 × $0.09894048/hour | $72.23 |
| 100 GiB balanced boot disk | 100 × $0.10/GiB-month | $10.00 |
| In-use external IPv4 (same networking model as existing pool) | 730 × $0.005/hour | $3.65 |
| **Incremental baseline** | | **$85.88** |

No commitments, Spot pricing or discounts assumed. Existing cluster-management,
app-disk, IAP/load-balancer and database costs are unchanged and excluded;
additional logging, traffic and KMS operations depend on use. There is no new
Cloud NAT. This estimate is not authorization to create a pool or spend money.
[Compute pricing](https://cloud.google.com/products/compute/pricing/general-purpose#e2-machine-types),
[disk pricing](https://cloud.google.com/compute/disks-image-pricing),
[IPv4 pricing](https://cloud.google.com/vpc/pricing).

## Checks

Use `tofu init -backend=false` and `tofu test` for the offline mocked plans.
Tests require an exact dedicated profile and reject Autopilot and undersized
machines. Initialize the instance's separate GCS backend and plan with its
variable file. The first plan must propose only the single new node pool.
Retain and apply that reviewed plan after approval, then require a clean plan
and verify the actual node's readiness, labels, taint and capacity. Commit both
Linux and local provider checksums so hosted validation can use the same lock.
