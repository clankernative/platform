# Registration has no native selections or mount witnesses. Mock plans do not
# establish a real workload identity, storage/P3 or execution permission.
mock_provider "kubernetes" {}

variables {
  app       = "calendar"
  namespace = "day2-native-enrollment"
  image     = "registry.example.com/day2/calendar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

run "registration_needs_only_identity_and_qualified_image" {
  command = plan

  assert {
    condition = (
      !kubernetes_deployment_v1.controller.wait_for_rollout &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].replicas) == 0 &&
      length(kubernetes_config_map_v1.inputs) == 0 &&
      kubernetes_deployment_v1.controller.spec[0].strategy[0].type == "Recreate" &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].image == var.image &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-epoch-controller"]) &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "calendar"])
    )
    error_message = "Registration must stay dormant and retain the qualified image and fixed real Controller command."
  }

  assert {
    condition = (
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume) == 0 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount) == 0 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].node_selector) == 0 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].toleration) == 0 &&
      !contains(keys(kubernetes_deployment_v1.controller.spec[0].template[0].metadata[0].annotations), "day2.dev/native-inputs") &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].automount_service_account_token &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].supplemental_groups) == 0 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].fs_group == null
    )
    error_message = "Dormant registration must contain no native inputs, node pin, mounts or projected credentials."
  }
}

run "activation_cannot_omit_native_inputs" {
  command = plan
  variables { activate = true }
  expect_failures = [
    var.bootstrap_alias,
    var.instance_json,
    var.enrollment_json,
    var.storage_json,
    var.host_state_path,
    var.node_profile,
    var.disk_device_group_id,
  ]
}

run "dormant_registration_still_requires_qualified_image" {
  command = plan
  variables { image = "registry.example.com/day2/calendar:latest" }
  expect_failures = [var.image]
}

run "registration_refuses_a_disk_group_grant" {
  command = plan
  variables { disk_device_group_id = 6 }
  expect_failures = [var.disk_device_group_id]
}
