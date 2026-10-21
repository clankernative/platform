# Native enrollment root

This separate GCS state root creates a dedicated key ring, software Ed25519
signing key and one explicit enabled version. Google generates the private key
inside Cloud KMS. It cannot be read from Terraform or a local private-key file.
The resources refuse accidental Terraform destruction. No automatic rotation or
primary/latest alias changes the trusted enrollment root.

The instance owns names, region and backend. After apply, read the exact
`root_version` and its public key, check the Ed25519 algorithm and SOFTWARE
protection, then pin the numeric version and canonical base64url public key in
`EnrollmentPolicy.root`. Store only those public values in the instance repo.
The KMS API must already be enabled.

This root creates a custom role containing only version metadata, public-key
read and signing, and adds the selected provisioner KSA's direct GKE Workload
Identity principal on this key. It creates no Google service account, KSA or
namespace and changes no project IAM bindings. App,
Shell and the node service account receive no signing grant. Keep hostNetwork
disabled so the workload uses GKE Workload Identity metadata authentication. The
issuer child shares the provisioner identity and privileged trust boundary.
Creating the root alone proves no native enrollment or live readiness.

See the [native enrollment contract](../../../../docs/CREDENTIAL-NATIVE-ENROLLMENT.md)
and Google's [software Ed25519 support](https://docs.cloud.google.com/kms/docs/algorithms).
