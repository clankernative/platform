# Public metadata observation is separate from key-scoped birth signing.
# Every binding adds one exact member; no complete policy is replaced.
data "google_project" "selected" { project_id = var.project_id }

locals {
  principal = "principal://iam.googleapis.com/projects/${data.google_project.selected.number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/${var.provisioner_namespace}/sa/${var.provisioner_service_account}"
  # GKE IAM uses zones for zonal resources, even when REST uses locations.
  cluster_name      = "projects/${var.project_id}/${var.cluster.scope == "zonal" ? "zones" : "locations"}/${var.cluster.location}/clusters/${var.cluster.name}"
  cluster_condition = "resource.type == 'container.googleapis.com/Cluster' && resource.name == '${local.cluster_name}'"
}

resource "google_project_iam_custom_role" "project" {
  project     = var.project_id
  role_id     = "${var.role_prefix}ProjectRead"
  title       = "Native enrollment selected project observation"
  permissions = ["resourcemanager.projects.get"]
}
resource "google_project_iam_member" "project" {
  project = var.project_id
  role    = google_project_iam_custom_role.project.name
  member  = local.principal
}

resource "google_project_iam_custom_role" "cluster" {
  project     = var.project_id
  role_id     = "${var.role_prefix}ClusterRead"
  title       = "Native enrollment selected cluster observation"
  permissions = ["container.clusters.get"]
}
resource "google_project_iam_member" "cluster" {
  project = var.project_id
  role    = google_project_iam_custom_role.cluster.name
  member  = local.principal
  condition {
    title       = "SelectedEnrollmentCluster"
    description = "Read only the exact selected GKE cluster metadata."
    expression  = local.cluster_condition
  }
}

resource "google_project_iam_custom_role" "service_account" {
  project     = var.project_id
  role_id     = "${var.role_prefix}ServiceAccountRead"
  title       = "Native enrollment selected service account observation"
  permissions = ["iam.serviceAccounts.get"]
}
resource "google_service_account_iam_member" "selected" {
  for_each           = var.service_accounts
  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value}"
  role               = google_project_iam_custom_role.service_account.name
  member             = local.principal
}

output "observer" {
  value = {
    principal        = local.principal
    cluster_resource = local.cluster_name
    service_accounts = var.service_accounts
  }
}
