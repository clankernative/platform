# Offline: the google provider is mocked.
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/example-project/serviceAccounts/day2-x86-qualify@example-project.iam.gserviceaccount.com"
      email = "day2-x86-qualify@example-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id = "example-project"
}

run "off_by_default" {
  command = plan

  assert {
    condition = (
      length(google_compute_instance.runner) == 0 &&
      length(google_compute_network.runner) == 0 &&
      length(google_compute_router_nat.runner) == 0 &&
      length(google_service_account.runner) == 0
    )
    error_message = "the runner and its network exist only when enabled"
  }
}

run "enabled_is_private_x86_and_iap_only" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
  }

  assert {
    condition = (
      google_compute_instance.runner[0].machine_type == "n2-standard-8" &&
      google_compute_instance.runner[0].boot_disk[0].initialize_params[0].image == "projects/debian-cloud/global/images/family/debian-13" &&
      length(google_compute_instance.runner[0].network_interface[0].access_config) == 0 &&
      google_compute_instance.runner[0].metadata["enable-oslogin"] == "TRUE" &&
      google_compute_instance.runner[0].metadata["block-project-ssh-keys"] == "TRUE"
    )
    error_message = "x86_64 Debian 13 VM with no external IP and OS Login only"
  }

  assert {
    condition = (
      google_compute_firewall.runner_iap_ssh[0].source_ranges == toset(["35.235.240.0/20"]) &&
      one(google_compute_firewall.runner_iap_ssh[0].allow).ports == tolist(["22"])
    )
    error_message = "SSH only from the IAP TCP forwarding range"
  }

  assert {
    condition     = length(google_artifact_registry_repository_iam_member.runner_push) == 0
    error_message = "no repository write access unless image_push_repository_id is set"
  }
}

run "refuses_arm_machine_types" {
  command = plan

  variables {
    enabled          = true
    operator_members = ["user:operator@example.com"]
    machine_type     = "t2a-standard-8"
  }

  expect_failures = [var.machine_type]
}

run "requires_an_operator_when_enabled" {
  command = plan

  variables {
    enabled = true
  }

  expect_failures = [google_compute_instance.runner]
}
