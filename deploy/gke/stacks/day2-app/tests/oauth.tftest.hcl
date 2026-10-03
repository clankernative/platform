# Structural plan oracle is also parsed by the native closed instance contract.
# These synthetic pins do not qualify an artifact, Google client or live IAM.
mock_provider "kubernetes" {}

variables {
  app_id                  = "example_app"
  namespace               = "app-example"
  image                   = "registry.example.com/day2/example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  artifact_id             = "9ef287e05cb53f593b35c140140e83306e8c487cca417ff9f23f58568340b6bb"
  installation            = "exampleco"
  environment             = "production"
  hosted_domain           = "example.com"
  edge_origin             = "https://example.test.example.com"
  runtime_resources       = { memory_mib = 512, cpu_millis = 1000, process_limit = 1024, http_concurrency = 4, shutdown_seconds = 30 }
  pod_pids_limit          = 1024
  backup_bucket           = "example-tools-example-backups"
  readers                 = ["qa@example.com"]
  writers                 = ["qa@example.com"]
  authority               = jsondecode(file("tests/oauth-instance.json")).apps.example_app.authority
  security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
  oauth_instance_json     = file("tests/oauth-instance.json")
  node_selector           = { "kubernetes.io/arch" = "amd64", "kubernetes.io/os" = "linux", "iam.gke.io/gke-metadata-server-enabled" = "true" }
}

override_data {
  target = data.kubernetes_config_map_v1.platform_contract
  values = { data = {
    APP_DOMAIN                   = "example.test.example.com"
    APP_NAMESPACE                = "app-example"
    IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/987654321"
    REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/app"
    REQUIRED_SERVICE_LABEL_VALUE = "example_app"
    SERVICE_ACCOUNT_NAME         = "runtime"
    OAUTH_APP_PROJECT            = "example-tools"
    OAUTH_APP_SERVICE_ACCOUNT    = "app-native@example-tools.iam.gserviceaccount.com"
    OAUTH_APP_SECRET_IDS         = "[\"custody_verifier\",\"custody_encryption\",\"shell_attestation\"]"
    OAUTH_SHELL_NAMESPACE        = "day2-security"
    OAUTH_SHELL_CONTRACT         = "security-shell-contract"
  } }
}

override_data {
  target = data.kubernetes_config_map_v1.security_shell_contract
  values = { data = {
    EDGE_ROLE                   = "security_shell"
    SECURITY_SHELL_ORIGIN       = "https://security.tools.example.com"
    IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/987654322"
    REAUTH_CALLBACK_URL         = "https://security.tools.example.com/_day2/reauth/callback"
    OAUTH_SHELL_SERVICE_ACCOUNT = "shell@example-tools.iam.gserviceaccount.com"
  } }
}

override_data {
  target = data.kubernetes_resource.oauth_runtime
  values = { object = { metadata = { name = "runtime", namespace = "app-example", annotations = { "iam.gke.io/gcp-service-account" = "app-native@example-tools.iam.gserviceaccount.com" } } } }
}

run "renders_the_native_selected_instance_without_rewriting_pins" {
  command = plan
  assert {
    condition     = jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]) == jsondecode(file("tests/oauth-instance.json"))
    error_message = "The deployment must preserve the canonical bindings, all exact versions, clients and native runtime fields."
  }
  assert {
    condition = (
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "example_app", "--edge"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].annotations["day2.dev/instance-sha256"] == sha256(kubernetes_config_map_v1.instance.data["instance.json"]) &&
      length(kubernetes_manifest.credentials) == 0 &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].service_account_name == "backup"
    )
    error_message = "OAuth uses the ordinary host with a pinned ConfigMap and native reads; backup keeps its separate identity."
  }
}

run "refuses_another_annotation" {
  command = plan
  override_data {
    target = data.kubernetes_resource.oauth_runtime
    values = { object = { metadata = { name = "runtime", namespace = "app-example", annotations = { "iam.gke.io/gcp-service-account" = "shell@example-tools.iam.gserviceaccount.com" } } } }
  }
  expect_failures = [terraform_data.oauth_admission]
}

run "provider_provisioning_stays_operator_only_beside_oauth" {
  command = plan
  variables {
    resource_catalog = {
      version = 1
      connections = { forge = {
        revision = 1
        provider = "gitea_actions"
        live     = { provider = "gitea_actions", endpoint = "https://git.example.com", credential_ref = { id = "forge-token", revision = 1 } }
      } }
      resources = {}
      policies  = {}
    }
    credential_operator = "operator@example.com"
    provider_credentials = [{
      credential_ref = { id = "forge-token", revision = 1 }
      secret_version = "projects/example-tools/secrets/forge-token/versions/3"
      fingerprint    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }]
  }
  assert {
    condition = (
      !can(jsondecode(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"]).oauth_clients) &&
      !can(jsondecode(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"]).oauth_runtime) &&
      !can(jsondecode(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"]).apps.example_app.oauth_connections) &&
      jsondecode(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"]).control == { version = 1, state_directory = "/srv/day2/.state/operator-control", operators = ["operator@example.com"], sources = {}, apps = {} } &&
      length(jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).control.secrets) == 5 &&
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.oauth_connections.calendar.registration.id == "calendar_client"
    )
    error_message = "Provider registration must keep its operator-only instance while the serving host keeps the selected OAuth references."
  }
}

run "refuses_a_different_artifact" {
  command = plan
  variables { artifact_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_a_different_installation" {
  command = plan
  variables { installation = "other_company" }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_no_shell_contract" {
  command = plan
  variables { security_shell_contract = null }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_metadata_disabled_node" {
  command = plan
  variables { node_selector = { "kubernetes.io/arch" = "amd64" } }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_extra_accounts" {
  command = plan
  variables {
    oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), { oauth_runtime = merge(jsondecode(file("tests/oauth-instance.json")).oauth_runtime, { apps = { example_app = { service_account = "app-native@example-tools.iam.gserviceaccount.com", accounts = { calendar = { kind = "iap_subject" }, other = { kind = "iap_subject" } } } } }) }))
  }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_a_client_container_at_another_version" {
  command = plan
  variables {
    oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), { control = merge(jsondecode(file("tests/oauth-instance.json")).control, { secrets = merge(jsondecode(file("tests/oauth-instance.json")).control.secrets, { calendar = { kind = "gcp_version", project_number = 123456789012, secret = "custody_verifier", version = 2 } }) }) }))
  }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_a_floating_key_version" {
  command = plan
  variables {
    oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), { control = merge(jsondecode(file("tests/oauth-instance.json")).control, { secrets = merge(jsondecode(file("tests/oauth-instance.json")).control.secrets, { verifier = { kind = "gcp_version", project_number = 123456789012, secret = "custody_verifier", version = "latest" } }) }) }))
  }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_an_ungranted_key_container" {
  command = plan
  variables {
    oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), { control = merge(jsondecode(file("tests/oauth-instance.json")).control, { secrets = merge(jsondecode(file("tests/oauth-instance.json")).control.secrets, { verifier = { kind = "gcp_version", project_number = 123456789012, secret = "ungranted_verifier", version = 1 } }) }) }))
  }
  expect_failures = [terraform_data.oauth_admission]
}

run "refuses_a_key_from_another_project" {
  command = plan
  variables {
    oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), { control = merge(jsondecode(file("tests/oauth-instance.json")).control, { secrets = merge(jsondecode(file("tests/oauth-instance.json")).control.secrets, { verifier = { kind = "gcp_version", project_number = 999999999999, secret = "custody_verifier", version = 1 } }) }) }))
  }
  expect_failures = [terraform_data.oauth_admission]
}
