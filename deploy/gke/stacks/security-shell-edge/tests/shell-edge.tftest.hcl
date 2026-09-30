mock_provider "google" {}
mock_provider "kubernetes" {}
mock_provider "cloudflare" {}

variables {
  project_id           = "example-tools"
  project_number       = "123456789012"
  namespace            = "day2-security"
  domain               = "security.tools.example.com"
  cloudflare_zone_id   = "0123456789abcdef0123456789abcdef"
  backend_service_name = "shell-backend"
  iap_members          = ["domain:example.com"]
  runtime_secret_ids   = ["oauth-custody", "oauth-encryption", "oauth-shell"]
  kube_dns_service_ip  = "10.30.0.10"
  cluster_cidrs        = ["10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"]
}

override_data {
  target = data.google_compute_backend_service.shell
  values = {
    generated_id = 5486495053471409653
    description  = "{\"kubernetes.io/service-name\":\"day2-security/security-shell\"}"
    iap          = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
  }
}

run "one_hostname_drives_the_edge_and_contract" {
  command = plan
  assert {
    condition = (
      output.origin == "https://security.tools.example.com" &&
      output.reauth_callback_url == "https://security.tools.example.com/_day2/reauth/callback" &&
      cloudflare_dns_record.shell.name == "security.tools.example.com" && !cloudflare_dns_record.shell.proxied &&
      kubernetes_ingress_v1.shell.spec[0].rule[0].host == "security.tools.example.com" &&
      kubernetes_manifest.certificate.manifest.spec.domains == ["security.tools.example.com"] &&
      kubernetes_manifest.backend.manifest.spec.iap.enabled &&
      kubernetes_manifest.frontend.manifest.spec.redirectToHttps.enabled &&
      kubernetes_config_map_v1.contract.data["EDGE_ROLE"] == "security_shell" &&
      kubernetes_config_map_v1.contract.data["SECURITY_SHELL_ORIGIN"] == output.origin &&
      kubernetes_config_map_v1.contract.data["REAUTH_CALLBACK_URL"] == output.reauth_callback_url &&
      output.iap_audience == "/projects/123456789012/global/backendServices/5486495053471409653" &&
      kubernetes_config_map_v1.contract.data["IAP_JWT_AUDIENCE"] == output.iap_audience
    )
    error_message = "DNS, TLS, routing, redirects and runtime origin must derive from the same installation hostname and dedicated IAP backend."
  }
  assert {
    condition = (
      toset(keys(google_secret_manager_secret_iam_member.shell)) == toset(var.runtime_secret_ids) &&
      alltrue([for grant in google_secret_manager_secret_iam_member.shell :
        grant.role == "roles/secretmanager.secretAccessor" &&
        grant.member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/example-tools.svc.id.goog/subject/ns/day2-security/sa/security-shell"
      ]) &&
      kubernetes_service_account_v1.shell.automount_service_account_token == false &&
      kubernetes_network_policy_v1.deny.spec[0].policy_types == tolist(["Ingress", "Egress"]) &&
      kubernetes_network_policy_v1.listener.spec[0].pod_selector[0].match_labels == kubernetes_service_v1.shell.spec[0].selector &&
      toset([for from in kubernetes_network_policy_v1.listener.spec[0].ingress[0].from : from.ip_block[0].cidr]) == toset(["35.191.0.0/16", "130.211.0.0/22"]) &&
      kubernetes_network_policy_v1.https.spec[0].egress[0].ports[0].port == "443"
    )
    error_message = "The dedicated shell principal alone receives named secrets; only the load balancer reaches the listener and provider egress uses HTTPS."
  }
}

run "a_different_company_selects_its_own_hostname" {
  command = plan
  variables { domain = "accounts.other.example.net" }
  assert {
    condition = (
      output.origin == "https://accounts.other.example.net" &&
      kubernetes_manifest.certificate.manifest.spec.domains == ["accounts.other.example.net"] &&
      cloudflare_dns_record.shell.name == "accounts.other.example.net" &&
      output.reauth_callback_url == "https://accounts.other.example.net/_day2/reauth/callback"
    )
    error_message = "A company's hostname must be an instance input with no platform hostname default."
  }
}

run "bootstrap_has_no_invented_audience" {
  command = plan
  variables { backend_service_name = "" }
  assert {
    condition     = output.iap_audience == "" && length(google_iap_web_backend_service_iam_binding.shell) == 0
    error_message = "An unresolved backend must not invent authentication authority."
  }
}

run "refuses_an_app_backend" {
  command = plan
  override_data {
    target = data.google_compute_backend_service.shell
    values = {
      description = "{\"kubernetes.io/service-name\":\"app-example/app\"}"
      iap         = [{ enabled = true, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
    }
  }
  expect_failures = [google_iap_web_backend_service_iam_binding.shell]
}

run "refuses_unprotected_backend" {
  command = plan
  override_data {
    target = data.google_compute_backend_service.shell
    values = {
      description = "{\"kubernetes.io/service-name\":\"day2-security/security-shell\"}"
      iap         = [{ enabled = false, oauth2_client_id = "", oauth2_client_secret = "", oauth2_client_secret_sha256 = "" }]
    }
  }
  expect_failures = [google_iap_web_backend_service_iam_binding.shell]
}

run "refuses_public_access" {
  command = plan
  variables { iap_members = ["allUsers"] }
  expect_failures = [var.iap_members]
}

run "refuses_app_namespace" {
  command = plan
  variables { namespace = "app-example" }
  expect_failures = [var.namespace]
}
