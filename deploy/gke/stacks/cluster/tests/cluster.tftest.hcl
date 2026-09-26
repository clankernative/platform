# Offline: the google provider is mocked.
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email = "day2-gke-nodes@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id                 = "example-project"
  shared_node_pod_pids_limit = 1024
}

run "shared_pool_runs_ubuntu_with_a_pod_pids_limit" {
  command = plan

  assert {
    condition     = google_container_node_pool.shared.node_config[0].image_type == "UBUNTU_CONTAINERD"
    error_message = "the COS kernel lacks Landlock, which the day2 worker sandbox requires"
  }

  assert {
    condition = (
      google_container_node_pool.shared.node_config[0].kubelet_config[0].pod_pids_limit == 1024 &&
      google_container_node_pool.shared.node_config[0].kubelet_config[0].cpu_cfs_quota == true
    )
    error_message = "every shared-pool pod is bounded by podPidsLimit and CFS quota stays enforced"
  }

  assert {
    condition = (
      google_container_node_pool.shared.node_config[0].machine_type == "c3-standard-4" &&
      google_container_node_pool.shared.autoscaling[0].min_node_count == 1 &&
      google_container_node_pool.shared.autoscaling[0].max_node_count == 3 &&
      google_container_node_pool.shared.upgrade_settings[0].max_surge == 1 &&
      google_container_node_pool.shared.upgrade_settings[0].max_unavailable == 0
    )
    error_message = "one x86_64 node, autoscaling to three, surging one at a time"
  }
}

run "nodes_use_workload_identity_not_their_own_credentials" {
  command = plan

  assert {
    condition = (
      google_container_cluster.primary.workload_identity_config[0].workload_pool == "example-project.svc.id.goog" &&
      output.cluster_workload_pool == "example-project.svc.id.goog"
    )
    error_message = "the cluster serves the project's Workload Identity pool"
  }

  assert {
    condition = (
      google_container_node_pool.shared.node_config[0].workload_metadata_config[0].mode == "GKE_METADATA" &&
      google_container_node_pool.shared.node_config[0].metadata["disable-legacy-endpoints"] == "true" &&
      google_container_node_pool.shared.node_config[0].service_account == "day2-gke-nodes@example-project.iam.gserviceaccount.com"
    )
    error_message = "pods reach the GKE metadata server, not the node identity or legacy endpoints"
  }
}

run "vpc_native_with_private_google_access_and_network_policy" {
  command = plan

  assert {
    condition = (
      google_compute_subnetwork.gke.private_ip_google_access == true &&
      google_container_cluster.primary.networking_mode == "VPC_NATIVE" &&
      google_container_cluster.primary.network_policy[0].enabled == true
    )
    error_message = "VPC-native cluster with Private Google Access and network policy enforcement"
  }
}

run "refuses_pids_limits_gke_refuses" {
  command = plan

  variables {
    shared_node_pod_pids_limit = 512
  }

  expect_failures = [var.shared_node_pod_pids_limit]
}

run "refuses_fractional_pids_limits" {
  command = plan

  variables {
    shared_node_pod_pids_limit = 2048.5
  }

  expect_failures = [var.shared_node_pod_pids_limit]
}

run "refuses_arm_machine_types" {
  command = plan

  variables {
    shared_node_machine_type = "t2a-standard-4"
  }

  expect_failures = [var.shared_node_machine_type]
}

run "declares_no_v1_only_resources" {
  command = plan

  assert {
    condition = length(regexall(
      "resource\\s+\"(google_cloud_identity_group|google_compute_instance|google_compute_firewall|google_compute_global_address|google_service_networking_connection|google_memorystore_instance|google_network_connectivity_service_connection_policy|google_iap_tunnel_instance_iam_member|google_compute_instance_iam_member|google_service_account_iam_member|google_project_service|terraform_data)\"",
      join("\n", [for f in fileset(path.module, "*.tf") : file("${path.module}/${f}")]),
    )) == 0
    error_message = "no bastions, tunnels, Google Groups RBAC, Memorystore, private services access or API enablement in this stack"
  }

  assert {
    condition = length(regexall(
      "resource\\s+\"google_container_node_pool\"\\s+\"",
      join("\n", [for f in fileset(path.module, "*.tf") : file("${path.module}/${f}")]),
    )) == 1
    error_message = "one shared node pool: no dedicated or video-composer pools"
  }
}
