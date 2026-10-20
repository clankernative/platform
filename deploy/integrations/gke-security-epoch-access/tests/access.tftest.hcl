# Synthetic selections and mocked providers only; these plans grant no access.
mock_provider "google" {
  mock_data "google_project" {
    defaults = { number = "123456789012" }
  }
}
mock_provider "kubernetes" {}

override_data {
  target = data.google_service_account.controller
  values = {
    name      = "projects/example-tools/serviceAccounts/epoch-controller@example-tools.iam.gserviceaccount.com"
    email     = "epoch-controller@example-tools.iam.gserviceaccount.com"
    unique_id = "223456789012345678901"
  }
}
override_data {
  target = data.google_service_account.app_reader
  values = {
    name      = "projects/example-tools/serviceAccounts/calendar-app@example-tools.iam.gserviceaccount.com"
    email     = "calendar-app@example-tools.iam.gserviceaccount.com"
    unique_id = "123456789012345678901"
  }
}
override_resource {
  target = google_project_iam_custom_role.metadata
  values = { name = "projects/example-tools/roles/metadata" }
}
override_resource {
  target = google_project_iam_custom_role.self_token
  values = { name = "projects/example-tools/roles/self_token" }
}
override_resource {
  target = google_project_iam_custom_role.storage
  values = { name = "projects/example-tools/roles/storage" }
}

variables {
  project_id           = "example-tools"
  project_number       = "123456789012"
  authority_scope      = { installation = "example", environment = "staging", app = "calendar" }
  controller_namespace = "epoch-system"
  controller_service_account = {
    email     = "epoch-controller@example-tools.iam.gserviceaccount.com"
    unique_id = "223456789012345678901"
  }
  app_reader = {
    email                      = "calendar-app@example-tools.iam.gserviceaccount.com"
    unique_id                  = "123456789012345678901"
    kubernetes_service_account = "runtime"
    workload_name              = "day2-calendar"
  }
  storage = {
    zone                  = "us-central1-a"
    disk_name             = "selected-disk"
    persistent_volume     = "selected-pv"
    claim_name            = "data"
    node_name             = "selected-node"
    compute_instance_name = "selected-instance"
  }
}

run "closed_google_permission_sets" {
  command = plan
  assert {
    condition = (
      toset(google_project_iam_custom_role.metadata.permissions) == toset(["container.clusters.get", "resourcemanager.projects.get"]) &&
      toset(google_project_iam_custom_role.self_token.permissions) == toset(["iam.serviceAccounts.get", "iam.serviceAccounts.getAccessToken"]) &&
      toset(google_project_iam_custom_role.storage.permissions) == toset(["compute.disks.get", "compute.instances.get"]) &&
      alltrue([for grant in google_project_iam_member.metadata : grant.role == "projects/example-tools/roles/metadata"])
    )
    error_message = "The new roles must be exact metadata/self-token permissions, without datastore mutations, signing, listing or administration."
  }
}

run "self_mint_never_crosses_from_app_to_controller" {
  command = plan
  assert {
    condition = (
      google_service_account_iam_member.self_token["controller"].service_account_id == "projects/example-tools/serviceAccounts/epoch-controller@example-tools.iam.gserviceaccount.com" &&
      google_service_account_iam_member.self_token["controller"].member == "serviceAccount:epoch-controller@example-tools.iam.gserviceaccount.com" &&
      google_service_account_iam_member.self_token["app"].service_account_id == "projects/example-tools/serviceAccounts/calendar-app@example-tools.iam.gserviceaccount.com" &&
      google_service_account_iam_member.self_token["app"].member == "serviceAccount:calendar-app@example-tools.iam.gserviceaccount.com" &&
      alltrue([for grant in google_service_account_iam_member.self_token : grant.role == "projects/example-tools/roles/self_token"]) &&
      google_service_account_iam_member.controller_workload.member == "serviceAccount:example-tools.svc.id.goog[epoch-system/calendar-epoch-controller]" &&
      google_service_account_iam_member.controller_workload.role == "roles/iam.workloadIdentityUser"
    )
    error_message = "Each account may mint only itself; only the selected controller KSA receives the new Workload Identity binding."
  }
}

run "compute_reads_are_resource_bound_and_controller_only" {
  command = plan
  assert {
    condition = (
      google_compute_disk_iam_member.controller.name == "selected-disk" &&
      google_compute_instance_iam_member.controller.instance_name == "selected-instance" &&
      google_compute_disk_iam_member.controller.zone == "us-central1-a" &&
      google_compute_instance_iam_member.controller.zone == "us-central1-a" &&
      google_compute_disk_iam_member.controller.role == "projects/example-tools/roles/storage" &&
      google_compute_instance_iam_member.controller.role == "projects/example-tools/roles/storage" &&
      google_compute_disk_iam_member.controller.member == "serviceAccount:epoch-controller@example-tools.iam.gserviceaccount.com" &&
      google_compute_instance_iam_member.controller.member == "serviceAccount:epoch-controller@example-tools.iam.gserviceaccount.com" &&
      alltrue([for grant in google_project_iam_member.metadata : grant.role != "projects/example-tools/roles/storage"])
    )
    error_message = "Compute reads belong only to the controller on the named disk/instance, never a project-wide storage grant or app grant."
  }
}

run "identity_reads_match_actual_fixed_routes" {
  command = plan
  assert {
    condition = (
      kubernetes_role_v1.identity["controller"].metadata[0].namespace == "epoch-system" &&
      kubernetes_role_v1.identity["app"].metadata[0].namespace == "app-calendar" &&
      alltrue([for role in kubernetes_role_v1.identity : alltrue([for rule in role.rule : toset(rule.verbs) == toset(["get"])])]) &&
      toset(one([for rule in kubernetes_role_v1.identity["app"].rule : rule if contains(rule.resources, "pods")]).resource_names) == toset(["day2-calendar-0"]) &&
      toset(one([for rule in kubernetes_role_v1.identity["controller"].rule : rule if contains(rule.resources, "deployments")]).resource_names) == toset(["calendar-epoch-controller"]) &&
      toset(one([for rule in kubernetes_role_v1.identity["app"].rule : rule if contains(rule.resources, "serviceaccounts")]).resource_names) == toset(["runtime"]) &&
      length([for rule in kubernetes_role_v1.identity["app"].rule : rule if contains(rule.resources, "replicasets")]) == 0
    )
    error_message = "Read only each actor's KSA/workload and required Pod lineage, never workload mutation or App access to controller ReplicaSets."
  }
}

run "token_review_is_the_only_cluster_create" {
  command = plan
  assert {
    condition = (
      length(kubernetes_cluster_role_v1.identity.rule) == 2 &&
      toset(one([for rule in kubernetes_cluster_role_v1.identity.rule : rule if contains(rule.resources, "tokenreviews")]).verbs) == toset(["create"]) &&
      toset(one([for rule in kubernetes_cluster_role_v1.identity.rule : rule if contains(rule.resources, "namespaces")]).resource_names) == toset(["app-calendar", "epoch-system"]) &&
      kubernetes_cluster_role_binding_v1.identity["app"].subject[0].name == "runtime" &&
      kubernetes_cluster_role_binding_v1.identity["app"].subject[0].namespace == "app-calendar" &&
      kubernetes_cluster_role_binding_v1.identity["controller"].subject[0].name == "calendar-epoch-controller" &&
      kubernetes_cluster_role_binding_v1.identity["controller"].subject[0].namespace == "epoch-system"
    )
    error_message = "Only the two named KSAs get namespace reads and TokenReview create; never credential mint, Secret read or arbitrary cluster writes."
  }
}

run "only_controller_can_inspect_selected_storage" {
  command = plan
  assert {
    condition = (
      toset(one(kubernetes_role_v1.storage.rule).resource_names) == toset(["data"]) &&
      toset(one(kubernetes_role_v1.storage.rule).verbs) == toset(["get"]) &&
      kubernetes_role_v1.storage.metadata[0].namespace == "app-calendar" &&
      toset(one([for rule in kubernetes_cluster_role_v1.storage.rule : rule if contains(rule.resources, "persistentvolumes")]).resource_names) == toset(["selected-pv"]) &&
      toset(one([for rule in kubernetes_cluster_role_v1.storage.rule : rule if contains(rule.resources, "nodes")]).resource_names) == toset(["selected-node"]) &&
      alltrue([for rule in kubernetes_cluster_role_v1.storage.rule : toset(rule.verbs) == toset(["get"])]) &&
      kubernetes_role_binding_v1.storage.subject[0].namespace == "epoch-system" &&
      kubernetes_role_binding_v1.storage.subject[0].name == "calendar-epoch-controller" &&
      kubernetes_cluster_role_binding_v1.storage.subject[0].name == "calendar-epoch-controller" &&
      kubernetes_service_account_v1.controller.metadata[0].annotations["iam.gke.io/gcp-service-account"] == var.controller_service_account.email &&
      !kubernetes_service_account_v1.controller.automount_service_account_token
    )
    error_message = "Exact PVC/PV/Node GETs are controller-only and cross-namespace explicitly; token mounts remain explicit workload work."
  }
}

run "recreated_controller_identity_refuses_all_new_google_grants" {
  command = plan
  override_data {
    target = data.google_service_account.controller
    values = {
      name      = "projects/example-tools/serviceAccounts/epoch-controller@example-tools.iam.gserviceaccount.com"
      email     = "epoch-controller@example-tools.iam.gserviceaccount.com"
      unique_id = "323456789012345678901"
    }
  }
  expect_failures = [
    google_project_iam_member.metadata["controller"], google_project_iam_member.metadata["app"],
    google_service_account_iam_member.self_token["controller"], google_service_account_iam_member.self_token["app"],
    google_compute_disk_iam_member.controller, google_compute_instance_iam_member.controller,
    google_service_account_iam_member.controller_workload,
  ]
}

run "reader_controller_alias_is_not_an_input_shape" {
  command = plan
  variables {
    app_reader = {
      email                      = "epoch-controller@example-tools.iam.gserviceaccount.com"
      unique_id                  = "223456789012345678901"
      kubernetes_service_account = "runtime"
      workload_name              = "day2-calendar"
    }
  }
  expect_failures = [var.app_reader]
}

run "wildcard_node_is_not_a_selection" {
  command = plan
  variables {
    storage = {
      zone                  = "us-central1-a"
      disk_name             = "selected-disk"
      persistent_volume     = "selected-pv"
      claim_name            = "data"
      node_name             = "*"
      compute_instance_name = "selected-instance"
    }
  }
  expect_failures = [var.storage]
}
