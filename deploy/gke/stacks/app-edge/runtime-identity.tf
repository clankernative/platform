resource "google_service_account" "runtime_identity" {
  count        = var.runtime_identity == null ? 0 : 1
  project      = var.project_id
  account_id   = var.runtime_identity.service_account_id
  display_name = "Day2 ${var.app_id} runtime"
}

resource "google_service_account_iam_member" "runtime_workload_identity" {
  count              = var.runtime_identity == null ? 0 : 1
  service_account_id = google_service_account.runtime_identity[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${local.namespace_name}/${local.runtime_service_account}]"
}

resource "google_service_account_iam_member" "runtime_token_creator" {
  for_each           = var.runtime_identity == null ? toset([]) : var.runtime_identity.token_creator_service_accounts
  service_account_id = each.value
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.runtime_identity[0].email}"
}
