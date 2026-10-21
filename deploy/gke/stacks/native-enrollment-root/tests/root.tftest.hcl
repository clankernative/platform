mock_provider "google" {
  mock_data "google_project" {
    defaults = { number = "123456789" }
  }
}

variables {
  project_id                  = "example-project"
  location                    = "us-central1"
  key_ring_name               = "native-enrollment"
  key_name                    = "calendar-root"
  provisioner_namespace       = "day2-native-enrollment"
  provisioner_service_account = "provisioner"
  signer_role_id              = "nativeEnrollmentRootSigner"
}

run "only_selected_provisioner_can_sign_this_key" {
  command = plan
  assert {
    condition = (
      toset(google_project_iam_custom_role.signer.permissions) == toset([
        "cloudkms.cryptoKeyVersions.get",
        "cloudkms.cryptoKeyVersions.viewPublicKey",
        "cloudkms.cryptoKeyVersions.useToSign",
      ]) &&
      google_kms_crypto_key_iam_member.provisioner.member == "principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/day2-native-enrollment/sa/provisioner"
    )
    error_message = "Only the exact provisioner KSA may receive the three fixed key-scoped permissions."
  }
}

run "only_software_ed25519_signing_with_explicit_version" {
  command = plan
  assert {
    condition = (
      google_kms_crypto_key.root.purpose == "ASYMMETRIC_SIGN" &&
      google_kms_crypto_key.root.skip_initial_version_creation &&
      google_kms_crypto_key.root.version_template[0].algorithm == "EC_SIGN_ED25519" &&
      google_kms_crypto_key.root.version_template[0].protection_level == "SOFTWARE" &&
      google_kms_crypto_key.root.rotation_period == null &&
      google_kms_crypto_key_version.root.state == "ENABLED"
    )
    error_message = "The root must use generated software Ed25519, an explicit enabled version and no automatic rotation."
  }
}
