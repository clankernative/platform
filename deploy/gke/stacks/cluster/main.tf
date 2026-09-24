resource "google_project_service" "api" {
  for_each           = toset(["compute.googleapis.com", "container.googleapis.com", "artifactregistry.googleapis.com", "iap.googleapis.com", "dns.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}
resource "google_compute_network" "cluster" {
  name                    = var.name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.api]
}
resource "google_compute_subnetwork" "cluster" {
  name                     = var.name
  network                  = google_compute_network.cluster.id
  region                   = var.region
  ip_cidr_range            = "10.20.0.0/20"
  private_ip_google_access = true
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.24.0.0/14"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.28.0.0/20"
  }
}
resource "google_compute_router" "cluster" {
  name    = var.name
  network = google_compute_network.cluster.id
  region  = var.region
}
resource "google_compute_router_nat" "cluster" {
  name                               = var.name
  router                             = google_compute_router.cluster.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.cluster.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}
resource "google_service_account" "nodes" {
  account_id   = "${var.name}-nodes"
  display_name = "Day2 GKE nodes"
  depends_on   = [google_project_service.api]
}
resource "google_project_iam_member" "nodes" {
  project = var.project_id
  role    = "roles/container.defaultNodeServiceAccount"
  member  = "serviceAccount:${google_service_account.nodes.email}"
}
resource "google_artifact_registry_repository" "apps" {
  repository_id = var.name
  location      = var.region
  format        = "DOCKER"
  depends_on    = [google_project_service.api]
}
resource "google_artifact_registry_repository_iam_member" "pull" {
  repository = google_artifact_registry_repository.apps.name
  location   = var.region
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.nodes.email}"
}
resource "google_container_cluster" "cluster" {
  name                     = var.name
  location                 = var.zone
  network                  = google_compute_network.cluster.id
  subnetwork               = google_compute_subnetwork.cluster.id
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = var.deletion_protection
  networking_mode          = "VPC_NATIVE"
  datapath_provider        = "ADVANCED_DATAPATH"
  enable_shielded_nodes    = true
  release_channel { channel = "REGULAR" }
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.admin_cidrs
      content { cidr_block = cidr_blocks.value }
    }
  }
  workload_identity_config { workload_pool = "${var.project_id}.svc.id.goog" }
  addons_config {
    gce_persistent_disk_csi_driver_config { enabled = true }
  }
  depends_on = [google_project_iam_member.nodes]
}
resource "google_container_node_pool" "apps" {
  name       = "apps"
  cluster    = google_container_cluster.cluster.name
  location   = var.zone
  node_count = var.node_count
  management {
    auto_repair  = true
    auto_upgrade = true
  }
  node_config {
    machine_type    = var.machine_type
    image_type      = "UBUNTU_CONTAINERD"
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    disk_size_gb    = 100
    disk_type       = "pd-balanced"
    metadata        = { disable-legacy-endpoints = "true" }
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    kubelet_config { pod_pids_limit = var.pod_pids_limit }
    linux_node_config { cgroup_mode = "CGROUP_MODE_V2" }
  }
  depends_on = [google_compute_router_nat.cluster, google_artifact_registry_repository_iam_member.pull]
}
output "cluster_name" { value = google_container_cluster.cluster.name }
output "network" { value = google_compute_network.cluster.self_link }
output "subnetwork" { value = google_compute_subnetwork.cluster.self_link }
output "registry" { value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.apps.repository_id}" }
output "pod_pids_limit" { value = var.pod_pids_limit }
