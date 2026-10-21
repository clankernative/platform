# Structural plan tests only. Synthetic selections do not supply native
# closed-schema admission, enrollment, first holder, storage/P3 or current roles.
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
  node_selector           = { "iam.gke.io/gke-metadata-server-enabled" = "true" }
  native_node_profile     = "native-fixture"
  oauth_instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), {
    control = merge(jsondecode(file("tests/oauth-instance.json")).control, {
      security_bootstraps = { native = jsondecode(file("tests/native-bootstrap.fixture.json")) }
    })
  }))
  native_enrollment_json = jsonencode({
    bootstrap = jsondecode(file("tests/native-bootstrap.fixture.json"))
    store     = jsondecode(file("tests/oauth-instance.json")).control.security_epochs.app_epoch
    runtime   = { architecture = "x86_64", node_name = "native-node", node_uid = "native-node-uid" }
  })
}

override_data {
  target = data.kubernetes_config_map_v1.platform_contract
  values = { data = {
    APP_DOMAIN                           = "example.test.example.com"
    APP_NAMESPACE                        = "app-example"
    IAP_JWT_AUDIENCE                     = "/projects/123456789012/global/backendServices/987654321"
    REQUIRED_SERVICE_LABEL_KEY           = "day2.dev/app"
    REQUIRED_SERVICE_LABEL_VALUE         = "example_app"
    SERVICE_ACCOUNT_NAME                 = "runtime"
    OAUTH_APP_PROJECT                    = "example-tools"
    OAUTH_APP_SERVICE_ACCOUNT            = "app-native@example-tools.iam.gserviceaccount.com"
    OAUTH_APP_SERVICE_ACCOUNT_UID        = "100000000000000000007"
    OAUTH_APP_SECRET_IDS                 = "[\"custody_verifier\",\"custody_encryption\",\"shell_attestation\"]"
    OAUTH_APP_PROVIDER_CLIENT_SECRET_IDS = "[\"google_calendar\"]"
    OAUTH_SHELL_NAMESPACE                = "day2-security"
    OAUTH_SHELL_CONTRACT                 = "security-shell-contract"
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
override_data {
  target = data.kubernetes_resource.native_namespace
  values = { object = { metadata = { name = "app-example", uid = "app-namespace-uid" } } }
}
override_data {
  target = data.kubernetes_resource.native_account
  values = { object = { metadata = { name = "runtime", namespace = "app-example", uid = "app-account-uid", annotations = { "iam.gke.io/gcp-service-account" = "app-native@example-tools.iam.gserviceaccount.com" } } } }
}
override_data {
  target = data.kubernetes_resources.workload
  values = { objects = [{ metadata = { name = "day2-example-app", namespace = "app-example", uid = "app-workload-uid" }, spec = { template = { spec = { containers = [{ name = "day2", image = "registry.example.com/day2/example@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }] } } } }] }
}

run "native_app_preserves_uid_and_uses_unprivileged_same_volume_attachment" {
  command = plan
  assert {
    condition = (
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].host_pid &&
      !kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].host_network &&
      !kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].automount_service_account_token &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].node_selector["kubernetes.io/hostname"] == "native-node" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].node_selector["day2.dev.node-restriction.kubernetes.io/enrollment"] == "native-fixture" &&
      !kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].privileged &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].capabilities[0].drop == tolist(["ALL"]) &&
      tonumber(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001
    )
    error_message = "Only the selected native node/host PID namespace may be added; the App remains unprivileged under its own KSA."
  }
  assert {
    condition = (
      kubernetes_config_map_v1.native_policy[0].immutable &&
      one([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].volume_mount : mount if mount.mount_path == "/etc/day2/native-enrollment.json"]).sub_path == "native-enrollment.json" &&
      one([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].volume_mount : mount if mount.mount_path == "/run/day2-native-enrollment"]).read_only &&
      one([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].volume_mount : mount if mount.mount_path == "/state"]).name == "state" &&
      length(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container) == 0 &&
      length(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].liveness_probe) == 0 &&
      kubernetes_cron_job_v1.backup.spec[0].suspend
    )
    error_message = "Native mode must retain the same PVC, a regular immutable policy and read-only socket parent, without mutating original ownership or running unsupported ordinary backup/restart paths."
  }
  assert {
    condition = (
      one([for volume in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].volume : volume if volume.name == "native-subject"]).projected[0].sources[0].service_account_token[0].audience == "day2-native-app-fixture" &&
      length(one([for volume in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].volume : volume if volume.name == "native-api"]).projected[0].sources) == 2
    )
    error_message = "Only the exact App subject audience and its own API token/CA are projected."
  }
}

run "native_app_refuses_missing_enrollment" {
  command = plan
  variables { native_enrollment_json = null }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_missing_native_node_profile" {
  command = plan
  variables { native_node_profile = null }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_foreign_epoch_store" {
  command = plan
  variables {
    native_enrollment_json = jsonencode({
      bootstrap = jsondecode(file("tests/native-bootstrap.fixture.json"))
      store     = { scope = { installation = "other", environment = "production", app = "example_app" } }
      runtime   = { architecture = "x86_64", node_name = "native-node", node_uid = "native-node-uid" }
    })
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_recreated_service_account" {
  command = plan
  override_data {
    target = data.kubernetes_resource.native_account
    values = { object = { metadata = { name = "runtime", namespace = "app-example", uid = "recreated-account-uid", annotations = { "iam.gke.io/gcp-service-account" = "app-native@example-tools.iam.gserviceaccount.com" } } } }
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_recreated_workload" {
  command = plan
  override_data {
    target = data.kubernetes_resources.workload
    values = { objects = [{ metadata = { name = "day2-example-app", namespace = "app-example", uid = "recreated-workload-uid" } }] }
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_another_image" {
  command = plan
  variables { image = "registry.example.com/day2/example@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
  expect_failures = [terraform_data.native_admission]
}

run "native_app_refuses_conflicting_node_pin" {
  command = plan
  variables { node_selector = { "iam.gke.io/gke-metadata-server-enabled" = "true", "kubernetes.io/hostname" = "other-node" } }
  expect_failures = [terraform_data.native_admission]
}

run "native_inputs_cannot_enable_an_unselected_app" {
  command = plan
  variables {
    oauth_instance_json = file("tests/oauth-instance.json")
    image               = "registry.example.com/day2/example@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
  expect_failures = [terraform_data.native_admission]
}
