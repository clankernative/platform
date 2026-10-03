# Synthetic structural plan fixture. Native closed instance, admitted artifact,
# routing, clock and HTTP guards are exercised by Rust conformance separately.
mock_provider "kubernetes" {}

variables {
  namespace     = "day2-security"
  image         = "registry.example.com/day2/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  instance_json = file("tests/instance.json")
}

override_data {
  target = data.kubernetes_config_map_v1.edge
  values = {
    data = {
      EDGE_ROLE                    = "security_shell"
      SERVICE_NAME                 = "security-shell"
      SERVICE_ACCOUNT_NAME         = "security-shell"
      REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/service"
      REQUIRED_SERVICE_LABEL_VALUE = "security-shell"
      SECURITY_SHELL_ORIGIN        = "https://security.tools.example.com"
      IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/987654321"
      OAUTH_SHELL_SERVICE_ACCOUNT  = "shell@example-tools.iam.gserviceaccount.com"
      OAUTH_SHELL_SECRET_IDS       = "[\"shell_attestation\",\"google_reauth\",\"google_calendar\"]"
    }
  }
}

run "dedicated_stateless_guarded_workload" {
  command = plan
  assert {
    condition = (
      tonumber(kubernetes_deployment_v1.shell.spec[0].replicas) == 1 &&
      kubernetes_deployment_v1.shell.spec[0].strategy[0].type == "Recreate" &&
      kubernetes_deployment_v1.shell.spec[0].template[0].metadata[0].labels["day2.dev/service"] == "security-shell" &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].service_account_name == "security-shell" &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].automount_service_account_token &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].host_network &&
      tonumber(kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].termination_grace_period_seconds == 35
    )
    error_message = "One stateless dedicated shell must consume the edge identity, without host or token access."
  }
  assert {
    condition = (
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-security-shell"]) &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json"]) &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].security_context[0].allow_privilege_escalation &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].resources[0].limits["memory"] == "512Mi" &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].resources[0].limits["cpu"] == "500m" &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].env[0].value == "sha256:${sha256(var.instance_json)}" &&
      kubernetes_config_map_v1.instance.data["instance.json"] == var.instance_json
    )
    error_message = "The native launcher must receive exactly the selected immutable metadata and admitted bounds."
  }
  assert {
    condition = (
      length(kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].volume) == 2 &&
      toset([for mount in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount : mount.mount_path]) == toset(["/srv/day2/instance.json", "/tmp"]) &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount[0].read_only &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount[0].sub_path == "instance.json" &&
      alltrue([for volume in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].volume : length(volume.persistent_volume_claim) == 0 && length(volume.secret) == 0 && length(volume.csi) == 0]) &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].readiness_probe[0].http_get[0].path == "/health/ready"
    )
    error_message = "Only regular read-only metadata and bounded scratch may be mounted; app storage and secrets stay in their owners."
  }
}

run "refuses_other_workload_identity" {
  command = plan
  variables {
    instance_json = jsonencode(merge(jsondecode(file("tests/instance.json")), { oauth_shell_transport = { service_account = "app@example-tools.iam.gserviceaccount.com" } }))
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_other_security_origin" {
  command = plan
  variables {
    instance_json = jsonencode(merge(jsondecode(file("tests/instance.json")), { security_shell = { origin = "https://app.tools.example.com", iap_audience = "/projects/123456789012/global/backendServices/987654321" } }))
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_custody_container_at_another_version" {
  command = plan
  variables {
    instance_json = jsonencode(merge(jsondecode(file("tests/instance.json")), { control = { secrets = merge(jsondecode(file("tests/instance.json")).control.secrets, { reauth = { kind = "gcp_version", project_number = 123456789012, secret = "custody_verifier", version = 2 } }) } }))
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_unbounded_resources" {
  command = plan
  variables {
    instance_json = jsonencode(merge(jsondecode(file("tests/instance.json")), { oauth_runtime = merge(jsondecode(file("tests/instance.json")).oauth_runtime, { shell_resources = { memory_mib = 512, cpu_millis = 500, process_limit = 1024, process_limit_enforced_by = "pod", http_concurrency = 33, shutdown_seconds = 30 } }) }))
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_floating_image" {
  command = plan
  variables { image = "registry.example.com/day2/shell:latest" }
  expect_failures = [var.image]
}

run "refuses_app_namespace" {
  command = plan
  variables { namespace = "app-workspace" }
  expect_failures = [var.namespace]
}

run "refuses_metadata_disabled_node" {
  command = plan
  variables { node_selector = { "iam.gke.io/gke-metadata-server-enabled" = "false" } }
  expect_failures = [var.node_selector]
}

run "refuses_unresolved_edge_contract" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.edge
    values = { data = {} }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_extra_secret_iam" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.edge
    values = {
      data = {
        EDGE_ROLE                    = "security_shell"
        SERVICE_NAME                 = "security-shell"
        SERVICE_ACCOUNT_NAME         = "security-shell"
        REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/service"
        REQUIRED_SERVICE_LABEL_VALUE = "security-shell"
        SECURITY_SHELL_ORIGIN        = "https://security.tools.example.com"
        IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/987654321"
        OAUTH_SHELL_SERVICE_ACCOUNT  = "shell@example-tools.iam.gserviceaccount.com"
        OAUTH_SHELL_SECRET_IDS       = "[\"shell_attestation\",\"google_reauth\",\"google_calendar\",\"custody_verifier\"]"
      }
    }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}
