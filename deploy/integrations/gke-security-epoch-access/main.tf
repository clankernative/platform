locals {
  app_namespace   = format("app-%s", replace(var.authority_scope.app, "_", "-"))
  controller_name = format("%s-epoch-controller", replace(var.authority_scope.app, "_", "-"))
  scope_id = substr(sha256(jsonencode({
    project = var.project_id
    scope   = var.authority_scope
  })), 0, 16)
  actors = {
    controller = {
      email     = var.controller_service_account.email
      unique_id = var.controller_service_account.unique_id
      namespace = var.controller_namespace
      account   = local.controller_name
      workload  = local.controller_name
      resource  = "deployments"
    }
    app = {
      email     = var.app_reader.email
      unique_id = var.app_reader.unique_id
      namespace = local.app_namespace
      account   = var.app_reader.kubernetes_service_account
      workload  = var.app_reader.workload_name
      resource  = "statefulsets"
    }
  }
  observed_accounts = {
    controller = data.google_service_account.controller
    app        = data.google_service_account.app_reader
  }
  selected_accounts = (
    data.google_project.selected.number == var.project_number &&
    alltrue([for key, actor in local.actors :
      local.observed_accounts[key].email == actor.email &&
      local.observed_accounts[key].unique_id == actor.unique_id
    ])
  )
}

data "google_project" "selected" {
  project_id = var.project_id
}

data "google_service_account" "controller" {
  project    = var.project_id
  account_id = split("@", var.controller_service_account.email)[0]
}

data "google_service_account" "app_reader" {
  project    = var.project_id
  account_id = split("@", var.app_reader.email)[0]
}

# These two metadata permissions need a project grant. This is deliberately not
# Viewer, list/connect, IAM administration or a claim of per-cluster isolation.
resource "google_project_iam_custom_role" "metadata" {
  project     = var.project_id
  role_id     = format("day2EpochMetadata_%s", local.scope_id)
  title       = "Day2 epoch native metadata reads"
  permissions = ["container.clusters.get", "resourcemanager.projects.get"]
}

resource "google_project_iam_member" "metadata" {
  for_each = local.actors
  project  = var.project_id
  role     = google_project_iam_custom_role.metadata.name
  member   = format("serviceAccount:%s", each.value.email)
  lifecycle {
    precondition {
      condition     = local.selected_accounts
      error_message = "Observed project/GSA identities must match the selected immutable identities."
    }
  }
}

# A controller or reader may get its OWN metadata and mint a token only as
# itself. This does not grant signing, delegated chains or App -> Controller.
resource "google_project_iam_custom_role" "self_token" {
  project     = var.project_id
  role_id     = format("day2EpochSelfToken_%s", local.scope_id)
  title       = "Day2 epoch own account token"
  permissions = ["iam.serviceAccounts.get", "iam.serviceAccounts.getAccessToken"]
}

resource "google_service_account_iam_member" "self_token" {
  for_each           = local.actors
  service_account_id = local.observed_accounts[each.key].name
  role               = google_project_iam_custom_role.self_token.name
  member             = format("serviceAccount:%s", each.value.email)
  lifecycle {
    precondition {
      condition     = local.selected_accounts
      error_message = "Never grant self-token access to a recreated, foreign or aliased identity."
    }
  }
}

# This role is bound on ONLY the named disk and instance, never at project
# scope. IAM resource names are not immutable disk/instance identity proofs.
resource "google_project_iam_custom_role" "storage" {
  project     = var.project_id
  role_id     = format("day2EpochStorageRead_%s", local.scope_id)
  title       = "Day2 epoch selected storage metadata"
  permissions = ["compute.disks.get", "compute.instances.get"]
}

resource "google_compute_disk_iam_member" "controller" {
  project = var.project_id
  zone    = var.storage.zone
  name    = var.storage.disk_name
  role    = google_project_iam_custom_role.storage.name
  member  = format("serviceAccount:%s", var.controller_service_account.email)
  lifecycle {
    precondition {
      condition     = local.selected_accounts
      error_message = "Storage metadata grants require the selected immutable accounts."
    }
  }
}

resource "google_compute_instance_iam_member" "controller" {
  project       = var.project_id
  zone          = var.storage.zone
  instance_name = var.storage.compute_instance_name
  role          = google_project_iam_custom_role.storage.name
  member        = format("serviceAccount:%s", var.controller_service_account.email)
  lifecycle {
    precondition {
      condition     = local.selected_accounts
      error_message = "Storage metadata grants require the selected immutable accounts."
    }
  }
}

resource "kubernetes_service_account_v1" "controller" {
  metadata {
    name      = local.controller_name
    namespace = var.controller_namespace
    annotations = {
      "iam.gke.io/gcp-service-account" = var.controller_service_account.email
    }
  }
  automount_service_account_token = false
}

# App's existing Workload Identity binding remains owned by app-edge.
resource "google_service_account_iam_member" "controller_workload" {
  service_account_id = local.observed_accounts["controller"].name
  role               = "roles/iam.workloadIdentityUser"
  member = format("serviceAccount:%s.svc.id.goog[%s/%s]",
  var.project_id, var.controller_namespace, kubernetes_service_account_v1.controller.metadata[0].name)
  lifecycle {
    precondition {
      condition     = local.selected_accounts
      error_message = "The controller workload binding must use the existing selected GSA."
    }
  }
}

resource "kubernetes_role_v1" "identity" {
  for_each = local.actors
  metadata {
    name      = format("day2-epoch-identity-%s-%s", each.key, local.scope_id)
    namespace = each.value.namespace
  }
  rule {
    api_groups     = [""]
    resources      = ["serviceaccounts"]
    resource_names = [each.value.account]
    verbs          = ["get"]
  }
  rule {
    api_groups     = ["apps"]
    resources      = [each.value.resource]
    resource_names = [each.value.workload]
    verbs          = ["get"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods"]
    # Controller Deployment Pod names are assigned later; native admission
    # checks the exact live Pod UID/owner. App is a single-replica StatefulSet.
    resource_names = each.key == "app" ? [format("%s-0", each.value.workload)] : null
    verbs          = ["get"]
  }
  dynamic "rule" {
    for_each = each.key == "controller" ? [true] : []
    content {
      api_groups = ["apps"]
      resources  = ["replicasets"]
      verbs      = ["get"]
    }
  }
}

resource "kubernetes_role_binding_v1" "identity" {
  for_each = local.actors
  metadata {
    name      = kubernetes_role_v1.identity[each.key].metadata[0].name
    namespace = each.value.namespace
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.identity[each.key].metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = each.value.account
    namespace = each.value.namespace
  }
}

resource "kubernetes_cluster_role_v1" "identity" {
  metadata { name = format("day2-epoch-identity-%s", local.scope_id) }
  rule {
    api_groups     = [""]
    resources      = ["namespaces"]
    resource_names = sort(distinct([local.app_namespace, var.controller_namespace]))
    verbs          = ["get"]
  }
  # TokenReview is a create-only, non-persisted authentication operation.
  # Kubernetes cannot resource-name restrict create. No token read or mint is
  # granted; native code accepts only its selected audience and bound identity.
  rule {
    api_groups = ["authentication.k8s.io"]
    resources  = ["tokenreviews"]
    verbs      = ["create"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "identity" {
  for_each = local.actors
  metadata { name = format("day2-epoch-identity-%s-%s", each.key, local.scope_id) }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.identity.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = each.value.account
    namespace = each.value.namespace
  }
}

resource "kubernetes_role_v1" "storage" {
  metadata {
    name      = format("day2-epoch-storage-%s", local.scope_id)
    namespace = local.app_namespace
  }
  rule {
    api_groups     = [""]
    resources      = ["persistentvolumeclaims"]
    resource_names = [var.storage.claim_name]
    verbs          = ["get"]
  }
}

resource "kubernetes_role_binding_v1" "storage" {
  metadata {
    name      = kubernetes_role_v1.storage.metadata[0].name
    namespace = local.app_namespace
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.storage.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = local.controller_name
    namespace = var.controller_namespace
  }
}

resource "kubernetes_cluster_role_v1" "storage" {
  metadata { name = format("day2-epoch-storage-%s", local.scope_id) }
  rule {
    api_groups     = [""]
    resources      = ["persistentvolumes"]
    resource_names = [var.storage.persistent_volume]
    verbs          = ["get"]
  }
  rule {
    api_groups     = [""]
    resources      = ["nodes"]
    resource_names = [var.storage.node_name]
    verbs          = ["get"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "storage" {
  metadata { name = format("day2-epoch-storage-%s", local.scope_id) }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.storage.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = local.controller_name
    namespace = var.controller_namespace
  }
}
