mock_provider "google" {}
mock_provider "kubernetes" {}
mock_provider "cloudflare" {}

variables {
  project_id              = "example-tools"
  project_number          = "123456789012"
  cluster_name            = "day2"
  cluster_location        = "us-central1-a"
  app_id                  = "example"
  domain                  = "example.apps.example.com"
  cloudflare_zone_id      = "0123456789abcdef0123456789abcdef"
  backend_service_name    = "app-backend"
  iap_members             = ["domain:example.com"]
  deployer_subjects       = ["user:owner@example.com"]
  sqlite_storage_gb       = 5
  storage_class_name      = "app-sqlite-rwo"
  kube_dns_service_ip     = "10.30.0.10"
  cluster_cidrs           = ["10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"]
  security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
}

override_data {
  target = data.google_compute_backend_service.app
  values = {
    generated_id = 5486495053471409653
    description  = "{\"kubernetes.io/service-name\":\"app-example/app\"}"
    iap          = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
  }
}

override_data {
  target = data.kubernetes_config_map_v1.security_shell_contract
  values = { data = {
    EDGE_ROLE                   = "security_shell"
    OAUTH_SHELL_SERVICE_ACCOUNT = "shell@example-tools.iam.gserviceaccount.com"
    IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/5486495053471409654"
  } }
}

run "grants_the_shell_only_this_app_backend" {
  command = plan
  assert {
    condition     = toset(google_iap_web_backend_service_iam_binding.app_access[0].members) == toset(["domain:example.com", "serviceAccount:shell@example-tools.iam.gserviceaccount.com"])
    error_message = "The app backend must admit precisely its human members and the dedicated shell workload."
  }
}

run "refuses_a_human_as_workload" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = { data = {
      EDGE_ROLE                   = "security_shell"
      OAUTH_SHELL_SERVICE_ACCOUNT = "human@example.com"
      IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/5486495053471409654"
    } }
  }
  expect_failures = [google_iap_web_backend_service_iam_binding.app_access]
}

run "refuses_the_app_as_shell_backend" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = { data = {
      EDGE_ROLE                   = "security_shell"
      OAUTH_SHELL_SERVICE_ACCOUNT = "shell@example-tools.iam.gserviceaccount.com"
      IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/5486495053471409653"
    } }
  }
  expect_failures = [google_iap_web_backend_service_iam_binding.app_access]
}
