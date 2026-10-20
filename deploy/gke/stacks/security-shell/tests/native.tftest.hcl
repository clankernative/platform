# Structural mock plans only, not native enrollment or serving qualification.
mock_provider "kubernetes" {}

variables {
  namespace           = "day2-security"
  image               = "registry.example.com/day2/shell@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  native_node_profile = "native-fixture"
  instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), {
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
  target = data.kubernetes_config_map_v1.edge
  values = { data = {
    EDGE_ROLE                    = "security_shell"
    SERVICE_NAME                 = "security-shell"
    SERVICE_ACCOUNT_NAME         = "security-shell"
    REQUIRED_SERVICE_LABEL_KEY   = "day2.dev/service"
    REQUIRED_SERVICE_LABEL_VALUE = "security-shell"
    SECURITY_SHELL_ORIGIN        = "https://security.tools.example.com"
    IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/987654321"
    OAUTH_SHELL_SERVICE_ACCOUNT  = "shell@example-tools.iam.gserviceaccount.com"
    OAUTH_SHELL_SECRET_IDS       = "[\"shell_attestation\",\"google_reauth\",\"google_calendar\"]"
  } }
}
override_data {
  target = data.kubernetes_resource.native_namespace
  values = { object = { metadata = { name = "day2-security", uid = "shell-namespace-uid" } } }
}
override_data {
  target = data.kubernetes_resource.native_account
  values = { object = { metadata = { name = "security-shell", namespace = "day2-security", uid = "shell-account-uid", annotations = { "iam.gke.io/gcp-service-account" = "shell@example-tools.iam.gserviceaccount.com" } } } }
}
override_data {
  target = data.kubernetes_resources.native_workload
  values = { objects = [{ metadata = { name = "security-shell", namespace = "day2-security", uid = "shell-workload-uid" } }] }
}

run "native_shell_is_unprivileged_and_has_no_api_subject_or_database_mount" {
  command = plan
  assert {
    condition = (
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].host_pid &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].host_network &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].automount_service_account_token &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].node_selector["kubernetes.io/hostname"] == "native-node" &&
      !kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].security_context[0].privileged &&
      kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].security_context[0].capabilities[0].drop == tolist(["ALL"]) &&
      tonumber(kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      length(kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].liveness_probe) == 0
    )
    error_message = "Native Shell requires the selected initial PID namespace while remaining unprivileged, without automatic original-owner recovery."
  }
  assert {
    condition = (
      kubernetes_config_map_v1.native_policy[0].immutable &&
      toset([for mount in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount : mount.mount_path]) == toset(["/srv/day2/instance.json", "/tmp", "/etc/day2/native-enrollment.json", "/run/day2-native-enrollment"]) &&
      one([for mount in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount : mount if mount.mount_path == "/etc/day2/native-enrollment.json"]).sub_path == "native-enrollment.json" &&
      alltrue([for mount in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].container[0].volume_mount : mount.read_only || mount.mount_path == "/tmp"]) &&
      alltrue([for volume in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].volume : length(volume.projected) == 0 && length(volume.persistent_volume_claim) == 0 && length(volume.secret) == 0 && length(volume.csi) == 0]) &&
      one([for volume in kubernetes_deployment_v1.shell.spec[0].template[0].spec[0].volume : volume if volume.name == "native-enrollment"]).host_path[0].type == "Directory"
    )
    error_message = "Only immutable public enrollment and the existing read-only socket parent are added; Shell receives no token, database, device, containerd or Controller credentials."
  }
}

run "native_shell_refuses_missing_enrollment" {
  command = plan
  variables { native_enrollment_json = null }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_missing_native_node_profile" {
  command = plan
  variables { native_node_profile = null }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_foreign_epoch_store" {
  command = plan
  variables {
    native_enrollment_json = jsonencode({
      bootstrap = jsondecode(file("tests/native-bootstrap.fixture.json"))
      store     = { scope = { installation = "other", environment = "production", app = "workspace" } }
      runtime   = { architecture = "x86_64", node_name = "native-node", node_uid = "native-node-uid" }
    })
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_recreated_service_account" {
  command = plan
  override_data {
    target = data.kubernetes_resource.native_account
    values = { object = { metadata = { name = "security-shell", namespace = "day2-security", uid = "recreated-account-uid", annotations = { "iam.gke.io/gcp-service-account" = "shell@example-tools.iam.gserviceaccount.com" } } } }
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_recreated_workload" {
  command = plan
  override_data {
    target = data.kubernetes_resources.native_workload
    values = { objects = [{ metadata = { name = "security-shell", namespace = "day2-security", uid = "recreated-shell-uid" } }] }
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_another_image" {
  command = plan
  variables { image = "registry.example.com/day2/shell@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
  expect_failures = [terraform_data.native_admission]
}

run "native_shell_refuses_multiple_fixed_enrollment_scopes" {
  command = plan
  variables {
    instance_json = jsonencode(merge(jsondecode(file("tests/oauth-instance.json")), {
      control = merge(jsondecode(file("tests/oauth-instance.json")).control, {
        security_bootstraps = { first = jsondecode(file("tests/native-bootstrap.fixture.json")), second = jsondecode(file("tests/native-bootstrap.fixture.json")) }
      })
    }))
  }
  expect_failures = [terraform_data.native_admission]
}

run "native_inputs_cannot_enable_an_unselected_shell" {
  command = plan
  variables { instance_json = file("tests/oauth-instance.json") }
  expect_failures = [terraform_data.native_admission]
}
