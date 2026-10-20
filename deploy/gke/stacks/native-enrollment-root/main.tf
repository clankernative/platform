# Only public identifiers enter state. Google generates and retains the private
# material. Creating a key does not enroll a native process or grant a role.
data "google_project" "selected" { project_id = var.project_id }

locals {
  provisioner_principal = "principal://iam.googleapis.com/projects/${data.google_project.selected.number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${var.provisioner_namespace}/sa/${var.provisioner_service_account}"
}

resource "google_kms_key_ring" "enrollment" {
  project  = var.project_id
  location = var.location
  name     = var.key_ring_name
  lifecycle { prevent_destroy = true }
}

resource "google_kms_crypto_key" "root" {
  name                          = var.key_name
  key_ring                      = google_kms_key_ring.enrollment.id
  purpose                       = "ASYMMETRIC_SIGN"
  skip_initial_version_creation = true
  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = "SOFTWARE"
  }
  lifecycle { prevent_destroy = true }
}

# An explicit version resource pins the actual generated numeric version, with
# no primary/latest alias or automatic rotation of enrollment trust.
resource "google_kms_crypto_key_version" "root" {
  crypto_key = google_kms_crypto_key.root.id
  state      = "ENABLED"
  lifecycle { prevent_destroy = true }
}

resource "google_project_iam_custom_role" "signer" {
  project     = var.project_id
  role_id     = var.signer_role_id
  title       = "Native enrollment root signer"
  description = "Read the selected enrollment version and public key, and sign issuer birth frames."
  permissions = [
    "cloudkms.cryptoKeyVersions.get",
    "cloudkms.cryptoKeyVersions.viewPublicKey",
    "cloudkms.cryptoKeyVersions.useToSign",
  ]
}

# Add one member on this key only; never replace the complete key/project policy.
# This direct KSA principal needs no service-account key or extra Google SA.
resource "google_kms_crypto_key_iam_member" "provisioner" {
  crypto_key_id = google_kms_crypto_key.root.id
  role          = google_project_iam_custom_role.signer.name
  member        = local.provisioner_principal
}

output "root_version" {
  description = "Exact numeric version; read and pin its Ed25519 public key in the instance policy."
  value       = google_kms_crypto_key_version.root.name
}

output "provisioner_principal" {
  description = "Exact direct Workload Identity principal granted signing on this key."
  value       = local.provisioner_principal
}
