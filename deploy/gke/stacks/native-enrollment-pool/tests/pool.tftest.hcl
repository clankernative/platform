mock_provider "google" {
  mock_data "google_container_cluster" {
    defaults = {
      enable_autopilot         = false
      workload_identity_config = [{ workload_pool = "example-project.svc.id.goog" }]
    }
  }
}
variables {
  project_id           = "example-project"
  zone                 = "us-central1-a"
  cluster_name         = "example"
  pool_name            = "native-enrollment"
  profile              = "calendar"
  machine_type         = "e2-highcpu-4"
  node_service_account = "nodes@example-project.iam.gserviceaccount.com"
  pod_pids_limit       = 1024
}
run "dedicated_single_node_with_no_surge_or_shared_pool_changes" {
  command = plan
  assert {
    condition = (
      google_container_node_pool.enrollment.node_count == 1 &&
      google_container_node_pool.enrollment.node_locations == toset([var.zone]) &&
      google_container_node_pool.enrollment.node_config[0].image_type == "UBUNTU_CONTAINERD" &&
      google_container_node_pool.enrollment.node_config[0].kubelet_config[0].pod_pids_limit == 1024 &&
      google_container_node_pool.enrollment.upgrade_settings[0].max_surge == 0 &&
      google_container_node_pool.enrollment.upgrade_settings[0].max_unavailable == 1 &&
      google_container_node_pool.enrollment.node_config[0].taint[0].effect == "NO_SCHEDULE" &&
      google_container_node_pool.enrollment.node_config[0].labels["day2.dev.node-restriction.kubernetes.io/enrollment"] == "calendar"
    )
    error_message = "Only one tainted Ubuntu node may serve this desired profile, without surge or autoscaling."
  }
}
run "refuses_small_machine" {
  command = plan
  variables { machine_type = "e2-highcpu-2" }
  expect_failures = [var.machine_type]
}
run "refuses_autopilot" {
  command = plan
  override_data {
    target = data.google_container_cluster.selected
    values = { enable_autopilot = true, workload_identity_config = [{ workload_pool = "example-project.svc.id.goog" }] }
  }
  expect_failures = [google_container_node_pool.enrollment]
}
