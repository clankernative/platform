# Zonal Standard GKE cluster for day2, its dedicated VPC and one shared node
# pool.
#
# Nodes run Ubuntu: the COS kernel does not enable the Landlock LSM, which the
# day2 worker sandbox requires. A kubelet podPidsLimit bounds every pod's
# processes, since day2 apps enforce their process limit per pod.
#
# Networking as deployed: VPC-native with fixed secondary ranges, Calico
# network policy, nodes with external IPs (no Cloud NAT), and a public
# control-plane IP endpoint without authorized networks. Changing any of that
# is a separate, reviewed change.
#
# Expects artifactregistry, compute, container, iap and secretmanager enabled
# (the project stack enables them).

locals {
  workload_pool = "${var.project_id}.svc.id.goog"
  node_sa_email = "serviceAccount:${google_service_account.nodes.email}"

  # Landlock: see the header.
  shared_node_image_type = "UBUNTU_CONTAINERD"
}

# API enablement moved to the project stack. Forget, never disable.
removed {
  from = google_project_service.cluster

  lifecycle {
    destroy = false
  }
}

# Logging to Cloud Logging is no longer optional.
moved {
  from = google_project_iam_member.nodes_logging_writer[0]
  to   = google_project_iam_member.nodes_logging_writer
}

resource "google_compute_network" "gke" {
  name                    = var.network_name
  project                 = var.project_id
  auto_create_subnetworks = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_subnetwork" "gke" {
  name                     = var.subnet_name
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.gke.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = var.pod_range_name
    ip_cidr_range = var.pod_cidr
  }

  secondary_ip_range {
    range_name    = var.svc_range_name
    ip_cidr_range = var.service_cidr
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The display name predates day2; renaming it is a no-risk in-place update
# left for a later change.
resource "google_service_account" "nodes" {
  account_id   = var.node_sa_name
  display_name = "Internal Tools GKE node service account"
  project      = var.project_id
}

resource "google_project_iam_member" "nodes_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = local.node_sa_email
}

resource "google_project_iam_member" "nodes_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = local.node_sa_email
}

resource "google_project_iam_member" "nodes_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = local.node_sa_email
}

resource "google_project_iam_member" "nodes_monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = local.node_sa_email
}

resource "google_project_iam_member" "nodes_resource_metadata_writer" {
  project = var.project_id
  role    = "roles/stackdriver.resourceMetadata.writer"
  member  = local.node_sa_email
}

resource "google_container_cluster" "primary" {
  name                     = var.cluster_name
  project                  = var.project_id
  location                 = var.zone
  network                  = google_compute_network.gke.id
  subnetwork               = google_compute_subnetwork.gke.id
  remove_default_node_pool = true
  initial_node_count       = 1
  networking_mode          = "VPC_NATIVE"

  # The live cluster was created with false. prevent_destroy below guards it;
  # turning this on is a state-only update left for a later change.
  deletion_protection = false

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  release_channel {
    channel = "STABLE"
  }

  maintenance_policy {
    daily_maintenance_window {
      start_time = var.daily_maintenance_window_start_time_utc
    }
  }

  workload_identity_config {
    workload_pool = local.workload_pool
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pod_range_name
    services_secondary_range_name = var.svc_range_name
  }

  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }

    dns_cache_config {
      enabled = true
    }

    gke_backup_agent_config {
      enabled = true
    }

    network_policy_config {
      disabled = false
    }
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  secret_manager_config {
    enabled = true
  }

  resource_labels = var.cluster_labels

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_iam_member.nodes_artifact_reader,
    google_project_iam_member.nodes_logging_writer,
    google_project_iam_member.nodes_metric_writer,
    google_project_iam_member.nodes_monitoring_viewer,
    google_project_iam_member.nodes_resource_metadata_writer,
  ]
}

resource "google_container_node_pool" "shared" {
  name       = var.node_pool_name
  project    = var.project_id
  cluster    = google_container_cluster.primary.name
  location   = var.zone
  node_count = var.shared_node_min_count

  lifecycle {
    ignore_changes = [
      node_count,
    ]
  }

  autoscaling {
    min_node_count = var.shared_node_min_count
    max_node_count = var.shared_node_max_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  # Replace one node at a time and bring its replacement up first. The 100 GB
  # boot disk keeps image churn below kubelet DiskPressure thresholds.
  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 1
    max_unavailable = 0
  }

  node_config {
    machine_type    = var.shared_node_machine_type
    image_type      = local.shared_node_image_type
    disk_size_gb    = 100
    disk_type       = "pd-balanced"
    service_account = google_service_account.nodes.email

    metadata = {
      disable-legacy-endpoints = "true"
    }

    labels = {
      pool       = var.node_pool_name
      managed_by = "opentofu"
    }

    # Many file-watching workloads share one host UID per node.
    linux_node_config {
      sysctls = {
        "fs.inotify.max_user_instances" = tostring(var.shared_node_inotify_max_user_instances)
        "fs.inotify.max_user_watches"   = tostring(var.shared_node_inotify_max_user_watches)
      }
    }

    # With a kubelet_config block present, CFS quota enforcement must stay on:
    # CPU limits, and workloads that read their cpu.max, depend on it.
    kubelet_config {
      pod_pids_limit = var.shared_node_pod_pids_limit
      cpu_cfs_quota  = true
    }

    gvnic {
      enabled = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
