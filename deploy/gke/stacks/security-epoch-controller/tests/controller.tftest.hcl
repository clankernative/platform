# Structural mock plans only. These minimal fixture objects are deliberately
# not native admission, enrollment, storage/P3 or serving qualification.
mock_provider "kubernetes" {}

variables {
  activate        = true
  app             = "calendar"
  bootstrap_alias = "native"
  namespace       = "day2-native-enrollment"
  image           = "registry.example.com/day2/calendar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  instance_json   = file("tests/oauth-instance.fixture.json")
  enrollment_json = file("tests/enrollment.json")
  storage_json    = file("tests/storage.json")
  host_state_path = "/var/lib/kubelet/plugins/kubernetes.io/csi/fixture-volume/globalmount"
  node_profile    = "fixture-native"
}

run "registration_does_not_start_a_placeholder_executor" {
  command = plan
  variables {
    activate        = false
    enrollment_json = "{}"
    instance_json   = jsonencode({ apps = { calendar = {} } })
  }
  assert {
    condition = (
      !kubernetes_deployment_v1.controller.wait_for_rollout &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].replicas) == 0 &&
      length(kubernetes_config_map_v1.inputs) == 0 &&
      kubernetes_deployment_v1.controller.spec[0].strategy[0].type == "Recreate" &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-epoch-controller"]) &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "calendar"])
    )
    error_message = "Registration must stay dormant and select the actual fixed Controller executable, never day2-host or a substitute."
  }
}

run "activated_trusted_controller_keeps_exact_separate_identity_and_mounts" {
  command = plan
  variables { activate = true }
  assert {
    condition = (
      tonumber(kubernetes_deployment_v1.controller.spec[0].replicas) == 1 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].service_account_name == "calendar-epoch-controller" &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].automount_service_account_token &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].host_pid &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].host_network &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].privileged &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].node_selector["kubernetes.io/hostname"] == "fixture-node"
    )
    error_message = "The trusted privileged Controller must retain its distinct existing identity and exact native node placement."
  }
  assert {
    condition = alltrue([
      for volume in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume :
      length(volume.host_path) == 0 || volume.host_path[0].type == "Directory"
    ])
    error_message = "No host directory or original file may be created/repaired by the workload manifest."
  }
  assert {
    condition = alltrue([
      for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount :
      mount.read_only || contains(["/state", "/run/day2-native-enrollment/storage"], mount.mount_path)
    ])
    error_message = "Only the actual selected state volume and provisioner-owned private peer child are writable."
  }
}

run "different_image_is_refused" {
  command = plan
  variables { image = "registry.example.com/day2/calendar@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
  expect_failures = [kubernetes_config_map_v1.inputs]
}

run "foreign_enrollment_profile_is_refused" {
  command = plan
  variables {
    enrollment_json = jsonencode(merge(jsondecode(file("tests/enrollment.json")), { bootstrap = {} }))
  }
  expect_failures = [kubernetes_config_map_v1.inputs]
}

run "different_disk_identity_is_refused" {
  command = plan
  variables {
    storage_json = jsonencode(merge(jsondecode(file("tests/storage.json")), { disk_id = "999999" }))
  }
  expect_failures = [kubernetes_config_map_v1.inputs]
}

run "foreign_node_is_refused" {
  command = plan
  variables {
    storage_json = jsonencode(merge(jsondecode(file("tests/storage.json")), { node = { name = "foreign-node", uid = "foreign-uid" } }))
  }
  expect_failures = [kubernetes_config_map_v1.inputs]
}
