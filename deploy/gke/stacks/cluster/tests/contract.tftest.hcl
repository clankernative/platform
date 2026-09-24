mock_provider "google" {}
variables {
  project_id  = "example-tools"
  region      = "us-central1"
  zone        = "us-central1-a"
  admin_cidrs = ["203.0.113.4/32"]
}
run "isolated_cluster" {
  command = plan
  assert {
    condition     = google_container_cluster.cluster.private_cluster_config[0].enable_private_nodes && google_container_cluster.cluster.datapath_provider == "ADVANCED_DATAPATH" && google_container_cluster.cluster.deletion_protection
    error_message = "Require private nodes, network policy enforcement and deletion protection."
  }
  assert {
    condition     = google_container_node_pool.apps.node_config[0].image_type == "UBUNTU_CONTAINERD" && google_container_node_pool.apps.node_config[0].kubelet_config[0].pod_pids_limit == 1024 && google_container_node_pool.apps.node_config[0].linux_node_config[0].cgroup_mode == "CGROUP_MODE_V2"
    error_message = "Node configuration must preserve the declared runtime containment contract."
  }
}
run "reject_public_api" {
  command = plan
  variables { admin_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.admin_cidrs]
}
run "reject_unbounded_pids" {
  command = plan
  variables { pod_pids_limit = 0 }
  expect_failures = [var.pod_pids_limit]
}
