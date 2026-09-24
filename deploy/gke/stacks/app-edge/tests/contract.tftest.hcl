mock_provider "google" {}
mock_provider "kubernetes" {}
override_data {
  target = data.google_project.current
  values = { number = "123456789" }
}
override_data {
  target = data.google_compute_backend_service.app
  values = { generated_id = 987654321 }
}
variables {
  project_id       = "example-tools"
  namespace        = "reports"
  domain           = "reports.example.com"
  dns_managed_zone = "example"
  kube_context     = "example"
  iap_members      = ["group:tools@example.com"]
}
run "bootstrap_denies_workload_audience" {
  command = plan
  assert {
    condition     = kubernetes_config_map_v1.contract.data["IAP_JWT_AUDIENCE"] == "" && length(google_iap_web_backend_service_iam_member.access) == 0
    error_message = "An undiscovered backend must not invent an audience or grant access."
  }
  assert {
    condition     = kubernetes_manifest.backend.manifest.spec.iap.enabled && kubernetes_ingress_v1.app.metadata[0].annotations["kubernetes.io/ingress.allow-http"] == "false" && !kubernetes_service_account_v1.runtime.automount_service_account_token && kubernetes_storage_class_v1.data.reclaim_policy == "Retain"
    error_message = "Require IAP, HTTPS, no pod credentials and retained storage."
  }
  assert {
    condition     = toset(kubernetes_network_policy_v1.app.spec[0].policy_types) == toset(["Ingress", "Egress"])
    error_message = "Both network directions must be restricted."
  }
}
run "exact_backend_audience" {
  command = plan
  variables { backend_service_name = "example-backend" }
  assert {
    condition     = kubernetes_config_map_v1.contract.data["IAP_JWT_AUDIENCE"] == "/projects/123456789/global/backendServices/987654321" && length(google_iap_web_backend_service_iam_member.access) == 1
    error_message = "Use the backend numeric ID and explicit principal grant."
  }
}
run "reject_public_access" {
  command = plan
  variables { iap_members = ["allUsers"] }
  expect_failures = [var.iap_members]
}
