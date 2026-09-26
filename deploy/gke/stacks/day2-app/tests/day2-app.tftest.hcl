# Offline: the kubernetes provider is mocked and the platform contract is an
# override, so this never contacts a cluster.
mock_provider "kubernetes" {}

override_data {
  target = data.kubernetes_config_map_v1.platform_contract
  values = {
    data = {
      APP_DOMAIN                   = "example.test.example.com"
      IAP_JWT_AUDIENCE             = "/projects/123456789012/global/backendServices/987654321"
      PVC_NAME                     = "data"
      SERVICE_NAME                 = "app"
      REQUIRED_SERVICE_LABEL_KEY   = "platform.example.com/service"
      REQUIRED_SERVICE_LABEL_VALUE = "app"
      O11Y_SERVICE_LABEL_KEY       = "telemetry.example.com/service"
      O11Y_SERVICE_LABEL_VALUE     = "example-api"
    }
  }
}

variables {
  app_id        = "example_app"
  namespace     = "app-example"
  image         = "registry.example.com/day2/example@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  artifact_id   = "9ef287e05cb53f593b35c140140e83306e8c487cca417ff9f23f58568340b6bb"
  installation  = "exampleco"
  environment   = "production"
  hosted_domain = "example.com"
  edge_origin   = "https://example.test.example.com"
  runtime_resources = {
    memory_mib       = 512
    cpu_millis       = 1000
    process_limit    = 1024
    http_concurrency = 4
    shutdown_seconds = 30
  }
  pod_pids_limit = 1024
  backup_bucket  = "example-tools-example-backups"
  readers        = ["qa@example.com"]
  writers        = ["qa@example.com"]
  authority = {
    version = 1
    admins  = []
    operations = {
      "example.list" = {
        actors = ["qa@example.com"]
        mode   = { kind = "read" }
        models = {}
      }
    }
  }
}

run "renders_instance_from_platform_contract" {
  command = plan

  assert {
    condition = jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]) == {
      installation = "exampleco"
      environment  = "production"
      identity     = { scheme = "google_iap", hosted_domain = "example.com" }
      apps = {
        example_app = {
          artifact  = "artifacts/9ef287e05cb53f593b35c140140e83306e8c487cca417ff9f23f58568340b6bb"
          readers   = ["qa@example.com"]
          writers   = ["qa@example.com"]
          authority = { version = 1, admins = [], operations = { "example.list" = { actors = ["qa@example.com"], mode = { kind = "read" }, models = {} } } }
          runtime = {
            kind = "linux_sqlite_single_v1"
            resources = {
              memory_mib                = 512
              cpu_millis                = 1000
              process_limit             = 1024
              process_limit_enforced_by = "pod"
              http_concurrency          = 4
              shutdown_seconds          = 30
            }
          }
          edge = {
            origin       = "https://example.test.example.com"
            iap_audience = "/projects/123456789012/global/backendServices/987654321"
          }
        }
      }
    }
    error_message = "instance.json must match day2's Instance shape, declare pod-held process limits and carry the contract's IAP audience"
  }

  assert {
    condition = (
      kubernetes_stateful_set_v1.day2.metadata[0].name == "day2-example-app" &&
      kubernetes_stateful_set_v1.day2.spec[0].replicas == "1" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].service_account_name == "runtime" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].node_selector["kubernetes.io/arch"] == "amd64" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].labels["platform.example.com/service"] == "app" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].labels["telemetry.example.com/service"] == "example-api"
    )
    error_message = "one replica, contract service account and labels, x86_64 nodes"
  }

  assert {
    condition = (
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-serve"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "example_app", "--edge"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].resources[0].limits["cpu"] == "1000m" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].resources[0].limits["memory"] == "512Mi" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].resources[0].requests["memory"] == "512Mi"
    )
    error_message = "day2-serve --edge with limits equal to the runtime profile"
  }

  assert {
    condition = (
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].run_as_user == "10001" &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem == true &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].allow_privilege_escalation == false &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].capabilities[0].drop == tolist(["ALL"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].security_context[0].seccomp_profile[0].type == "RuntimeDefault"
    )
    error_message = "non-root 10001, read-only root, no privilege escalation, no capabilities, RuntimeDefault seccomp"
  }
}

run "accepts_a_pod_bound_tighter_than_the_profile" {
  command = plan

  variables {
    runtime_resources = {
      memory_mib       = 512
      cpu_millis       = 1000
      process_limit    = 4096
      http_concurrency = 4
      shutdown_seconds = 30
    }
    pod_pids_limit = 1024
  }
}

run "refuses_a_pod_bound_looser_than_the_profile" {
  command = plan

  variables {
    pod_pids_limit = 2048
  }

  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_a_pod_bound_gke_cannot_set" {
  command = plan

  variables {
    pod_pids_limit = 512
  }

  expect_failures = [var.pod_pids_limit]
}

run "refuses_placeholder_authority" {
  command = plan

  variables {
    authority = {
      version    = 1
      admins     = []
      operations = {}
    }
  }

  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_origin_that_differs_from_contract" {
  command = plan

  variables {
    edge_origin = "https://other.example.com"
  }

  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_profile_above_namespace_maximum" {
  command = plan

  variables {
    runtime_resources = {
      memory_mib       = 8192
      cpu_millis       = 1000
      process_limit    = 1024
      http_concurrency = 4
      shutdown_seconds = 30
    }
  }

  expect_failures = [kubernetes_config_map_v1.instance]
}

run "state_ownership_is_idempotent_with_only_cap_chown" {
  command = plan

  assert {
    condition = (
      jsonencode(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[0].command) == jsonencode(["/busybox/chown", "10001:10001", "/srv/day2/.state"]) &&
      jsonencode(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[0].security_context[0].capabilities[0].add) == jsonencode(["CHOWN"])
    )
    error_message = "the state-ownership init container only chowns (idempotent under CAP_CHOWN); day2 itself chmods .state to 0700 as its owner"
  }
}

run "backs_up_hourly_beside_the_app_pod_to_the_backup_bucket" {
  command = plan

  assert {
    condition = (
      kubernetes_cron_job_v1.backup.metadata[0].name == "day2-example-app-backup" &&
      kubernetes_cron_job_v1.backup.metadata[0].namespace == "app-example" &&
      kubernetes_cron_job_v1.backup.spec[0].schedule == "17 * * * *" &&
      kubernetes_cron_job_v1.backup.spec[0].timezone == "Etc/UTC" &&
      kubernetes_cron_job_v1.backup.spec[0].concurrency_policy == "Forbid" &&
      kubernetes_cron_job_v1.backup.spec[0].starting_deadline_seconds == 600 &&
      kubernetes_cron_job_v1.backup.spec[0].successful_jobs_history_limit == 3 &&
      kubernetes_cron_job_v1.backup.spec[0].failed_jobs_history_limit == 3 &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].backoff_limit == 1 &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].active_deadline_seconds == 1800
    )
    error_message = "One hourly UTC backup at a time, bounded start and run deadlines, one retry and short history."
  }

  assert {
    condition = (
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].service_account_name == "backup" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].automount_service_account_token == false &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].restart_policy == "Never" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].node_selector["kubernetes.io/arch"] == "amd64"
    )
    error_message = "The backup pod runs as the backup service account (Workload Identity) with no mounted token."
  }

  assert {
    condition = (
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].metadata[0].labels["platform.example.com/service"] == "backup" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].metadata[0].labels["telemetry.example.com/service"] == "example-api" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].metadata[0].labels["app.kubernetes.io/name"] == "day2-example-app-backup" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].metadata[0].labels["platform.example.com/service"] == "backup"
    )
    error_message = "Backup pods carry the tenancy service=backup and o11y labels, and neither the Service selector value nor the StatefulSet's name."
  }

  assert {
    condition = (
      length(kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].affinity[0].pod_affinity[0].required_during_scheduling_ignored_during_execution) == 1 &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].affinity[0].pod_affinity[0].required_during_scheduling_ignored_during_execution[0].topology_key == "kubernetes.io/hostname" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].affinity[0].pod_affinity[0].required_during_scheduling_ignored_during_execution[0].label_selector[0].match_labels == tomap({ "app.kubernetes.io/name" = "day2-example-app" }) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].labels["app.kubernetes.io/name"] == "day2-example-app"
    )
    error_message = "The ReadWriteOnce state volume requires the backup pod on the app pod's node."
  }

  assert {
    condition = (
      length(kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container) == 1 &&
      length(kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].init_container) == 0 &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container[0].image == kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].image &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container[0].command == tolist(["/usr/local/bin/day2-backup"]) &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container[0].args == tolist(["/srv/day2/instance.json", "example_app", "/backup/snapshot", "--upload-gcs", "example-tools-example-backups", "--object-prefix", "example_app"]) &&
      length(kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container[0].env) == 0 &&
      jsonencode([for mount in kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container[0].volume_mount : [mount.name, mount.mount_path, mount.sub_path == null ? "" : mount.sub_path, mount.read_only == true]]) == jsonencode([
        ["instance", "/srv/day2/instance.json", "instance.json", true],
        ["state", "/srv/day2/.state", "", false],
        ["tmp", "/tmp", "", false],
        ["backup", "/backup", "", false],
      ]) &&
      jsonencode([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].volume_mount : [mount.name, mount.mount_path, mount.sub_path == null ? "" : mount.sub_path, mount.read_only == true] if mount.name != "tmp"]) == jsonencode([
        ["instance", "/srv/day2/instance.json", "instance.json", true],
        ["state", "/srv/day2/.state", "", false],
      ]) &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].volume[0].config_map[0].name == "day2-example-app-instance" &&
      kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].volume[1].persistent_volume_claim[0].claim_name == "data"
    )
    error_message = "One container: day2-backup from the StatefulSet's exact app image, with the same instance, state and artifact paths, uploading to the app-edge bucket."
  }

  assert {
    condition = alltrue([
      for container in kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].container :
      container.security_context[0].run_as_user == "10001" &&
      container.security_context[0].run_as_non_root == true &&
      container.security_context[0].read_only_root_filesystem == true &&
      container.security_context[0].allow_privilege_escalation == false &&
      container.security_context[0].privileged == false &&
      container.security_context[0].capabilities[0].drop == tolist(["ALL"]) &&
      length(coalesce(container.security_context[0].capabilities[0].add, [])) == 0 &&
      container.security_context[0].seccomp_profile[0].type == "RuntimeDefault" &&
      can(regex("@sha256:[0-9a-f]{64}$", container.image))
    ])
    error_message = "The backup container is non-root 10001 with a read-only root, no capabilities, RuntimeDefault seccomp and a digest-pinned image."
  }

  # No shell and no second image: nothing in the backup pod but day2-backup.
  assert {
    condition = alltrue([
      for forbidden in ["/bin/sh", "curl", "busybox", "tar -", "SCRIPT"] :
      !strcontains(jsonencode(kubernetes_cron_job_v1.backup.spec), forbidden)
    ])
    error_message = "The backup pod runs no shell script or uploader image."
  }
}

run "backup_schedule_is_configurable" {
  command = plan

  variables {
    backup_schedule = "5 */6 * * *"
  }

  assert {
    condition     = kubernetes_cron_job_v1.backup.spec[0].schedule == "5 */6 * * *"
    error_message = "backup_schedule sets the CronJob schedule."
  }
}

run "refuses_a_backup_bucket_that_is_not_a_bucket_name" {
  command = plan

  variables {
    backup_bucket = "gs://example-tools-example-backups"
  }

  expect_failures = [var.backup_bucket]
}

run "refuses_a_backup_deadline_past_the_hour" {
  command = plan

  variables {
    backup_active_deadline_seconds = 7200
  }

  expect_failures = [var.backup_active_deadline_seconds]
}
