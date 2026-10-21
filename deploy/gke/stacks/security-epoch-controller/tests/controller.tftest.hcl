# Structural mock plans only. These minimal fixture objects are deliberately
# not native admission, enrollment, storage/P3 or serving qualification.
mock_provider "kubernetes" {}

variables {
  activate             = true
  app                  = "calendar"
  bootstrap_alias      = "native"
  namespace            = "day2-native-enrollment"
  image                = "registry.example.com/day2/calendar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  instance_json        = file("tests/oauth-instance.fixture.json")
  enrollment_json      = file("tests/enrollment.json")
  storage_json         = file("tests/storage.json")
  host_state_path      = "/var/lib/kubelet/plugins/kubernetes.io/csi/fixture-volume/globalmount"
  node_profile         = "fixture-native"
  disk_device_group_id = 6
}

run "activated_trusted_controller_keeps_exact_separate_identity_and_mounts" {
  command = plan
  variables { activate = true }
  assert {
    condition = (
      tonumber(kubernetes_deployment_v1.controller.spec[0].replicas) == 1 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "calendar"]) &&
      kubernetes_deployment_v1.controller.spec[0].template[0].metadata[0].annotations["day2.dev/controller-mode"] == "initial" &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].service_account_name == "calendar-epoch-controller" &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].automount_service_account_token &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].host_pid &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].host_network &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].privileged &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume) == 8 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount) == 11 &&
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
      mount.read_only || contains(["/state", "/run/day2-native-enrollment/storage", "/tmp"], mount.mount_path)
    ])
    error_message = "Only the actual selected state volume, provisioner-owned private peer child and pod-local worker scratch are writable."
  }
}

run "activated_controller_reference_matches_existing_enrollment_volume" {
  command = plan
  assert {
    condition = (
      length([
        for volume in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume : volume
        if try(volume.name == "enrollment" && volume.host_path[0].path == "/run/day2-native-enrollment" &&
        volume.host_path[0].type == "Directory", false)
      ]) == 1 &&
      length([
        for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount : mount
        if try(mount.name == "enrollment" && mount.mount_path == "/run/day2-native-enrollment" &&
        mount.read_only && mount.sub_path == null, false)
      ]) == 1 &&
      length([
        for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount : mount
        if try(mount.name == "enrollment" && mount.mount_path == "/run/day2-native-enrollment-reference" &&
        mount.read_only && mount.sub_path == null, false)
      ]) == 1 &&
      length([
        for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount : mount
        if try(mount.name == "storage-peer" && mount.mount_path == "/run/day2-native-enrollment/storage" &&
        !mount.read_only && mount.sub_path == null, false)
      ]) == 1
    )
    error_message = "The active Controller must reuse the existing enrollment volume for both read-only roots while retaining only the canonical private storage child as writable."
  }
}

run "read_only_observation_selects_closed_command_before_process_start" {
  command = plan
  variables { observe_preparation_read_only = true }
  assert {
    condition = (
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-epoch-controller"]) &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].args == tolist(["--observe-preparation-read-only", "/srv/day2/instance.json", "calendar"]) &&
      kubernetes_deployment_v1.controller.spec[0].template[0].metadata[0].annotations["day2.dev/controller-mode"] == "preparation-read-only" &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].liveness_probe) == 0 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].startup_probe) == 0 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].readiness_probe[0].http_get[0].path == "/health/ready" &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].readiness_probe[0].http_get[0].port == "health" &&
      !kubernetes_deployment_v1.controller.wait_for_rollout &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].host_pid &&
      !kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].automount_service_account_token &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].privileged &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume) == 8 &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount) == 11 &&
      length([
        for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount : mount
        if try(mount.name == "enrollment" && mount.mount_path == "/run/day2-native-enrollment-reference" &&
        mount.read_only && mount.sub_path == null, false)
      ]) == 1
    )
    error_message = "Observation must select the closed diagnostic command before startup, retain normal native identity/mount guards, omit restart probes, and retain failing readiness because the diagnostic opens no health listener."
  }
}

run "dormant_registration_cannot_start_observation" {
  command = plan
  variables {
    activate                      = false
    observe_preparation_read_only = true
    bootstrap_alias               = null
    instance_json                 = null
    enrollment_json               = null
    storage_json                  = null
    host_state_path               = null
    node_profile                  = null
    disk_device_group_id          = null
  }
  expect_failures = [var.observe_preparation_read_only]
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

run "active_mount_is_required" {
  command = plan
  variables { host_state_path = null }
  expect_failures = [var.host_state_path]
}

run "activated_controller_adds_only_disk_dac_group_without_volume_ownership_mutation" {
  command = plan
  assert {
    condition = (
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].supplemental_groups) == 1 &&
      contains([
        for group in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].supplemental_groups : tonumber(group)
      ], 6) &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].run_as_user) == 10001 &&
      tonumber(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].run_as_group) == 10001 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].fs_group == null &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].init_container) == 0 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-epoch-controller"])
    )
    error_message = "Only the activated trusted Controller may add disk GID6; preserve primary UID/GID10001, no fsGroup/init-container ownership repair, and the exact native executable."
  }
}

run "missing_disk_group_is_refused" {
  command = plan
  variables { disk_device_group_id = null }
  expect_failures = [var.disk_device_group_id]
}

run "zero_disk_group_is_refused" {
  command = plan
  variables { disk_device_group_id = 0 }
  expect_failures = [var.disk_device_group_id]
}

run "fractional_disk_group_is_refused" {
  command = plan
  variables { disk_device_group_id = 6.5 }
  expect_failures = [var.disk_device_group_id]
}

run "negative_disk_group_is_refused" {
  command = plan
  variables { disk_device_group_id = -1 }
  expect_failures = [var.disk_device_group_id]
}

run "too_large_disk_group_is_refused" {
  command = plan
  variables { disk_device_group_id = 2147483648 }
  expect_failures = [var.disk_device_group_id]
}

run "instance_selected_group_is_used_without_a_node_global_default" {
  command = plan
  variables { disk_device_group_id = 42 }
  assert {
    condition = (
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].supplemental_groups) == 1 &&
      contains([
        for group in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].supplemental_groups : tonumber(group)
      ], 42)
    )
    error_message = "Use exactly the operator's explicit observed group; never substitute a global node/image assumption."
  }
}

run "activated_controller_has_bounded_pod_local_worker_scratch" {
  command = plan
  assert {
    condition = (
      length([
        for volume in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].volume : volume
        if try(volume.name == "tmp" && length(volume.empty_dir) == 1 &&
          volume.empty_dir[0].medium == "Memory" && volume.empty_dir[0].size_limit == "64Mi" &&
        length(volume.host_path) == 0 && length(volume.persistent_volume_claim) == 0, false)
      ]) == 1 &&
      length([
        for mount in kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].volume_mount : mount
        if try(mount.name == "tmp" && mount.mount_path == "/tmp" && !mount.read_only && mount.sub_path == null, false)
      ]) == 1 &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].security_context[0].fs_group == null &&
      length(kubernetes_deployment_v1.controller.spec[0].template[0].spec[0].init_container) == 0
    )
    error_message = "Active artifact admission needs one writable 64Mi memory emptyDir at /tmp; keep the root read-only, scratch off host/persistent storage, and no ownership repair."
  }
}
