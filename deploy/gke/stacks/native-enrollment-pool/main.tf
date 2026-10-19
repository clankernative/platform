# Separate state/root: this never updates the existing cluster or shared pool.
# One common node is desired placement DATA. Actual node/boot/runtime identity
# and current native role stages must still be acquired by the issuer.
data "google_container_cluster" "selected" {
  project  = var.project_id
  location = var.zone
  name     = var.cluster_name
}

resource "google_container_node_pool" "enrollment" {
  project        = var.project_id
  location       = var.zone
  cluster        = var.cluster_name
  name           = var.pool_name
  node_locations = [var.zone]
  node_count     = 1

  management {
    auto_repair  = true
    auto_upgrade = true
  }
  # A replacement deliberately interrupts this disposable single-node profile.
  # No surge node, overlapping enrollment generation or standby holder.
  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 0
    max_unavailable = 1
  }
  node_config {
    machine_type    = var.machine_type
    image_type      = "UBUNTU_CONTAINERD"
    disk_size_gb    = 100
    disk_type       = "pd-balanced"
    service_account = var.node_service_account
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    metadata        = { disable-legacy-endpoints = "true" }
    labels = {
      "day2.dev.node-restriction.kubernetes.io/enrollment" = var.profile
      "managed_by"                                         = "opentofu"
    }
    taint {
      key    = "day2.dev/native-enrollment"
      value  = var.profile
      effect = "NO_SCHEDULE"
    }
    workload_metadata_config { mode = "GKE_METADATA" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    kubelet_config {
      pod_pids_limit = var.pod_pids_limit
      cpu_cfs_quota  = true
    }
  }
  lifecycle {
    precondition {
      condition     = !data.google_container_cluster.selected.enable_autopilot && data.google_container_cluster.selected.location == var.zone
      error_message = "The native profile requires the selected zonal GKE Standard cluster."
    }
    precondition {
      condition     = length(data.google_container_cluster.selected.workload_identity_config) == 1
      error_message = "The selected cluster must have Workload Identity enabled."
    }
  }
}

output "placement" {
  description = "Pass to native_enrollment_placement on the selected app and shell roots. Desired data, never enrollment authority."
  value       = { pool_name = var.pool_name, profile = var.profile }
}
