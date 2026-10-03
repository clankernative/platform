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
  oauth_runtime           = { service_account_id = "app-native", custody_secret_ids = ["custody_verifier", "custody_encryption"], attestation_secret_ids = ["shell_attestation"] }
}

override_data {
  target = data.google_compute_backend_service.app
  values = {
    generated_id = 987654321
    description  = "{\"kubernetes.io/service-name\":\"app-example/app\"}"
    iap          = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
  }
}

override_data {
  target = data.kubernetes_config_map_v1.security_shell_contract
  values = { data = {
    EDGE_ROLE                   = "security_shell"
    OAUTH_SHELL_SERVICE_ACCOUNT = "shell@example-tools.iam.gserviceaccount.com"
    IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/987654322"
    OAUTH_SHELL_SECRET_IDS      = "[\"google_reauth\",\"google_calendar\",\"shell_attestation\"]"
  } }
}

override_resource {
  target = google_service_account.app_calls
  values = { email = "app-native@example-tools.iam.gserviceaccount.com", name = "projects/example-tools/serviceAccounts/app-native@example-tools.iam.gserviceaccount.com" }
}

run "one_native_identity_with_exact_read_and_key_grants" {
  command = plan
  assert {
    condition = (
      kubernetes_service_account_v1.runtime.metadata[0].annotations["iam.gke.io/gcp-service-account"] == "app-native@example-tools.iam.gserviceaccount.com" &&
      google_service_account_iam_member.app_call_workload[0].member == "serviceAccount:example-tools.svc.id.goog[app-example/runtime]" &&
      length(google_service_account_iam_member.app_call_signer) == 0 &&
      length(google_service_account_iam_member.app_call_workload) == 1
    )
    error_message = "OAuth-only pods must have one linked GSA, with no JWT signing grant."
  }
  assert {
    condition = (
      toset(google_project_iam_custom_role.oauth_edge_reads[0].permissions) == toset(["compute.projects.get", "compute.backendServices.get", "compute.urlMaps.get", "compute.targetHttpsProxies.get", "compute.globalForwardingRules.get"]) &&
      google_project_iam_member.oauth_edge_reads[0].member == "serviceAccount:app-native@example-tools.iam.gserviceaccount.com" &&
      toset(keys(google_secret_manager_secret_iam_member.oauth_keys)) == toset(["custody_verifier", "custody_encryption", "shell_attestation"]) &&
      alltrue([for grant in values(google_secret_manager_secret_iam_member.oauth_keys) : grant.project == "example-tools" && grant.member == "serviceAccount:app-native@example-tools.iam.gserviceaccount.com" && grant.role == "roles/secretmanager.secretAccessor"])
    )
    error_message = "Native app facts need exactly five Compute read methods and the selected key containers, never OAuth clients."
  }
  assert {
    condition = (
      kubernetes_config_map_v1.platform_contract.data["OAUTH_APP_SERVICE_ACCOUNT"] == "app-native@example-tools.iam.gserviceaccount.com" &&
      kubernetes_config_map_v1.platform_contract.data["SERVICE_ACCOUNT_NAME"] == "runtime" &&
      kubernetes_config_map_v1.platform_contract.data["OAUTH_SHELL_NAMESPACE"] == "day2-security" &&
      toset(jsondecode(kubernetes_config_map_v1.platform_contract.data["OAUTH_APP_SECRET_IDS"])) == toset(["custody_verifier", "custody_encryption", "shell_attestation"])
    )
    error_message = "The workload contract must publish the actual identity and named grants selected by this edge."
  }
}

run "reuses_the_existing_app_call_identity" {
  command = plan
  variables {
    app_calls = { service_account_id = "app-native", issuer_backend = "", receiver_backend = "", incoming_workloads = [], serving_readers = [], workload_name = "day2-example", serving_api_cidr = "10.1.0.2/32" }
  }
  override_resource {
    target = google_service_account.app_calls
    values = { email = "app-native@example-tools.iam.gserviceaccount.com", name = "projects/example-tools/serviceAccounts/app-native@example-tools.iam.gserviceaccount.com" }
  }
  assert {
    condition = (
      length(google_service_account.app_calls) == 1 && length(google_service_account_iam_member.app_call_workload) == 1 &&
      kubernetes_config_map_v1.platform_contract.data["APP_CALL_WORKLOAD_EMAIL"] == kubernetes_config_map_v1.platform_contract.data["OAUTH_APP_SERVICE_ACCOUNT"] &&
      google_project_iam_member.oauth_edge_reads[0].member == "serviceAccount:app-native@example-tools.iam.gserviceaccount.com"
    )
    error_message = "Existing app-call state addresses and signing grants must remain while OAuth uses the same pod identity."
  }
}

run "refuses_conflicting_app_call_identity" {
  command = plan
  variables {
    app_calls = { service_account_id = "other-native", issuer_backend = "", receiver_backend = "", incoming_workloads = [], serving_readers = [], workload_name = "day2-example", serving_api_cidr = "10.1.0.2/32" }
  }
  override_resource {
    target = google_service_account.app_calls
    values = { email = "other-native@example-tools.iam.gserviceaccount.com", name = "projects/example-tools/serviceAccounts/other-native@example-tools.iam.gserviceaccount.com" }
  }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}

run "refuses_custody_on_the_shell" {
  command = plan
  variables {
    oauth_runtime = { service_account_id = "app-native", custody_secret_ids = ["google_reauth", "custody_encryption"], attestation_secret_ids = ["shell_attestation"] }
  }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}

run "refuses_shell_credentials_through_csi" {
  command = plan
  variables { runtime_secret_ids = ["google_calendar"] }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}

run "refuses_attestation_not_granted_to_shell" {
  command = plan
  variables {
    oauth_runtime = { service_account_id = "app-native", custody_secret_ids = ["custody_verifier", "custody_encryption"], attestation_secret_ids = ["other_attestation"] }
  }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}

run "refuses_a_different_shell_project" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = { data = {
      EDGE_ROLE                   = "security_shell"
      OAUTH_SHELL_SERVICE_ACCOUNT = "shell@example-tools.iam.gserviceaccount.com"
      IAP_JWT_AUDIENCE            = "/projects/999999999999/global/backendServices/987654322"
      OAUTH_SHELL_SECRET_IDS      = "[\"google_reauth\",\"google_calendar\",\"shell_attestation\"]"
    } }
  }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}

run "refuses_unresolved_app_backend" {
  command = plan
  variables { backend_service_name = "" }
  expect_failures = [kubernetes_config_map_v1.platform_contract]
}
