# Offline: the kubernetes provider is mocked and the platform contract is an
# override, so this never contacts a cluster.
mock_provider "kubernetes" {}

run "preserves_explicit_credential_client_membership" {
  command = plan
  variables {
    readers = ["qa@example.com", "credential_client:client_keys"]
    writers = ["credential_client:client_keys"]
  }
  assert {
    condition     = contains(jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.readers, "credential_client:client_keys") && jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.writers == ["credential_client:client_keys"]
    error_message = "Client keys must receive an explicit family selector without being rewritten as human accounts."
  }
}

run "wires_private_app_calls_into_the_normal_host" {
  command = plan
  override_data {
    target = data.kubernetes_config_map_v1.platform_contract
    values = { data = {
      APP_DOMAIN                   = "example.test.example.com"
      IAP_JWT_AUDIENCE             = "/projects/123/global/backendServices/1"
      APP_CALL_ISSUER_AUDIENCE     = "/projects/123/global/backendServices/2"
      APP_CALL_RECEIVER_AUDIENCE   = "/projects/123/global/backendServices/3"
      APP_CALL_WORKLOAD_EMAIL      = "example-call@example-tools.iam.gserviceaccount.com"
      PVC_NAME                     = "data"
      SERVICE_NAME                 = "app"
      REQUIRED_SERVICE_LABEL_KEY   = "platform.example.com/service"
      REQUIRED_SERVICE_LABEL_VALUE = "app"
    } }
  }
  variables {
    app_calls = {
      workload_key                = { id = "workload-1", secret_version = "projects/123/secrets/workload/versions/1" }
      issuer_key                  = { issuer = "example-issuer", id = "issuer-1", secret_version = "projects/123/secrets/issuer/versions/1" }
      serving_snapshot_config_map = "active-app-serving"
      serving = { example_app = {
        target         = { company = "exampleco", environment = "production", app = "example_app" }
        project_number = 123
        location       = "us-central1-a"
        cluster        = "day2"
        namespace      = "app-example"
        workload       = "day2-example-app"
        workload_email = "example-call@example-tools.iam.gserviceaccount.com"
        deployment     = { id = "deployment", revision = "sha256:0000000000000000000000000000000000000000000000000000000000000000" }
      } }
      outgoing = {}
      incoming = {}
    }
  }
  assert {
    condition     = contains(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].args, "--app-calls") && jsondecode(kubernetes_config_map_v1.app_calls[0].data["host.json"]).workload_email == "example-call@example-tools.iam.gserviceaccount.com"
    error_message = "The real day2-serve entrypoint must receive its fixed private host bindings."
  }
  assert {
    condition     = kubernetes_stateful_set_v1.day2.metadata[0].annotations["day2.dev/artifact"] == "sha256:9ef287e05cb53f593b35c140140e83306e8c487cca417ff9f23f58568340b6bb" && length(kubernetes_manifest.app_call_keys) == 1
    error_message = "Serving evidence must expose the exact artifact and keys must use the managed CSI mount."
  }
  assert {
    condition     = length([for volume in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].volume : volume if volume.name == "app-call-selection" && volume.config_map[0].optional]) == 1
    error_message = "The host can become ready before activation publishes the selector; calls still fail closed until it exists."
  }
}

run "infrastructure_preserves_software_after_release_handoff" {
  command = plan
  variables {
    release_managed = true
    app_calls = {
      workload_key = { id = "workload-1", secret_version = "projects/123/secrets/workload/versions/1" }
      issuer_key = { issuer = "example-issuer", id = "issuer-1", secret_version = "projects/123/secrets/issuer/versions/1" }
      serving_snapshot_config_map = "active-app-serving"
      serving = {}
      outgoing = {}
      incoming = {}
    }
  }
  override_data {
    target = data.kubernetes_config_map_v1.platform_contract
    values = { data = {
      APP_DOMAIN = "example.test.example.com"
      IAP_JWT_AUDIENCE = "/projects/123/global/backendServices/1"
      APP_CALL_ISSUER_AUDIENCE = "/projects/123/global/backendServices/2"
      APP_CALL_RECEIVER_AUDIENCE = "/projects/123/global/backendServices/3"
      APP_CALL_WORKLOAD_EMAIL = "example-call@example-tools.iam.gserviceaccount.com"
      PVC_NAME = "data"
      SERVICE_NAME = "app"
      REQUIRED_SERVICE_LABEL_KEY = "platform.example.com/service"
      REQUIRED_SERVICE_LABEL_VALUE = "app"
    } }
  }
  override_data {
    target = data.kubernetes_resource.release
    values = { object = {
      metadata = { name = "day2-example-app", namespace = "app-example", annotations = {
        "day2.dev/release-effect" = "effect-two", "day2.dev/release-id" = "release-two"
      } }
      spec = { template = {
        metadata = { annotations = {
          "day2.dev/installation" = "exampleco", "day2.dev/environment" = "production", "day2.dev/app" = "example_app"
          "day2.dev/artifact" = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "day2.dev/instance-sha256" = "released-instance", "day2.dev/release-id" = "release-two"
        } }
        spec = {
          containers = [{ name = "day2", image = "registry.example.com/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", env = [{ name = "DAY2_EXPECTED_ARTIFACT", value = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }] }]
          volumes = [{ name = "instance", configMap = { name = "day2-release-two" } }]
        }
      } }
    } }
  }
  assert {
    condition = kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].image == "registry.example.com/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" && kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].env[0].value == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    error_message = "An infrastructure plan must keep the released image and artifact guard."
  }
  assert {
    condition = kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].volume[0].config_map[0].name == "day2-release-two" && kubernetes_stateful_set_v1.day2.metadata[0].annotations["day2.dev/release-effect"] == "effect-two" && kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].annotations["day2.dev/release-id"] == "release-two"
    error_message = "Infrastructure must preserve the immutable release instance and reconciliation markers."
  }
}

override_data {
  target = data.kubernetes_config_map_v1.security_shell_contract
  values = {
    data = {
      EDGE_ROLE                   = "security_shell"
      SECURITY_SHELL_ORIGIN       = "https://security.tools.example.com"
      IAP_JWT_AUDIENCE            = "/projects/123456789012/global/backendServices/987654322"
      REAUTH_CALLBACK_URL         = "https://security.tools.example.com/_day2/reauth/callback"
      OAUTH_SHELL_SERVICE_ACCOUNT = "security-shell@example-tools.iam.gserviceaccount.com"
    }
  }
}

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

run "renders_the_installation_shell_from_its_contract" {
  command = plan
  variables {
    security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
  }
  assert {
    condition     = jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).oauth_shell_transport.service_account == "security-shell@example-tools.iam.gserviceaccount.com"
    error_message = "The runtime must receive the dedicated shell workload identity from the same installation contract."
  }
  assert {
    condition = jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).security_shell == {
      origin       = "https://security.tools.example.com"
      iap_audience = "/projects/123456789012/global/backendServices/987654322"
    }
    error_message = "The per-app runtime instance must carry the origin and audience read from the installation shell contract."
  }
}

run "refuses_an_unresolved_shell_contract" {
  command = plan
  variables {
    security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
  }
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = {
      data = {
        EDGE_ROLE             = "security_shell"
        SECURITY_SHELL_ORIGIN = "https://security.tools.example.com"
        IAP_JWT_AUDIENCE      = ""
        REAUTH_CALLBACK_URL   = "https://security.tools.example.com/_day2/reauth/callback"
      }
    }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_an_app_contract_as_the_shell" {
  command = plan
  variables {
    security_shell_contract = { namespace = "app-example", name = "platform-contract" }
  }
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = {
      data = {
        EDGE_ROLE             = "app"
        SECURITY_SHELL_ORIGIN = "https://security.tools.example.com"
        IAP_JWT_AUDIENCE      = "/projects/123456789012/global/backendServices/987654322"
        REAUTH_CALLBACK_URL   = "https://security.tools.example.com/_day2/reauth/callback"
      }
    }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_the_app_origin_as_the_shell" {
  command = plan
  variables {
    security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
  }
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = {
      data = {
        EDGE_ROLE             = "security_shell"
        SECURITY_SHELL_ORIGIN = "https://example.test.example.com"
        IAP_JWT_AUDIENCE      = "/projects/123456789012/global/backendServices/987654322"
        REAUTH_CALLBACK_URL   = "https://example.test.example.com/_day2/reauth/callback"
      }
    }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_the_app_audience_as_the_shell" {
  command = plan
  variables {
    security_shell_contract = { namespace = "day2-security", name = "security-shell-contract" }
  }
  override_data {
    target = data.kubernetes_config_map_v1.security_shell_contract
    values = {
      data = {
        EDGE_ROLE             = "security_shell"
        SECURITY_SHELL_ORIGIN = "https://security.tools.example.com"
        IAP_JWT_AUDIENCE      = "/projects/123456789012/global/backendServices/987654321"
        REAUTH_CALLBACK_URL   = "https://security.tools.example.com/_day2/reauth/callback"
      }
    }
  }
  expect_failures = [kubernetes_config_map_v1.instance]
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

run "admits_everyone_at_the_hosted_domain" {
  command = plan

  variables {
    readers = ["domain:example.com", "qa@example.com"]
    writers = ["domain:example.com"]
  }

  assert {
    condition = (
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.readers == ["domain:example.com", "qa@example.com"] &&
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.writers == ["domain:example.com"]
    )
    error_message = "domain:<hosted_domain> is rendered into readers and writers unchanged"
  }
}

run "refuses_a_domain_other_than_the_hosted_domain" {
  command = plan

  variables {
    readers = ["domain:example.org"]
  }

  expect_failures = [kubernetes_config_map_v1.instance]
}

run "refuses_an_uppercase_domain_entry" {
  command = plan

  variables {
    writers = ["domain:Example.com"]
  }

  expect_failures = [var.writers]
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
    condition = (
      one([for volume in kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].volume : volume.empty_dir[0] if volume.name == "tmp"]).medium == "Memory" &&
      one([for volume in kubernetes_cron_job_v1.backup.spec[0].job_template[0].spec[0].template[0].spec[0].volume : volume.empty_dir[0] if volume.name == "tmp"]).size_limit ==
      one([for volume in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].volume : volume.empty_dir[0] if volume.name == "tmp"]).size_limit
    )
    error_message = "day2-backup copies the worker executable into /tmp as day2-serve does, so the backup Job's memory /tmp is the app pod's size."
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

run "renders_explicit_schedules_and_signed_ingress" {
  command = plan
  variables {
    resource_catalog = {
      version = 1
      connections = {
        forge = {
          revision = 1
          provider = "gitea_actions"
          live = {
            provider           = "gitea_actions"
            endpoint           = "https://git.example.com"
            credential_ref     = { id = "token", revision = 1 }
            signing_secret_ref = { id = "signer", revision = 1 }
          }
        }
      }
      resources = {}
      policies  = {}
    }
    schedules = { "example.refresh" = { actor = "owner@example.com", disabled = true } }
    ingress   = { gitea = { actor = "owner@example.com", connection = { id = "forge", revision = 1 } } }
  }
  assert {
    condition = (
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.schedules["example.refresh"].disabled &&
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.ingress.gitea.connection.id == "forge" &&
      jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).resources.connections.forge.live.signing_secret_ref.id == "signer"
    )
    error_message = "Explicit trigger actors, pauses and secret references must survive rendering."
  }
}

run "rejects_signed_ingress_without_catalog" {
  command = plan
  variables {
    ingress = { gitea = { actor = "owner@example.com", connection = { id = "forge", revision = 1 } } }
  }
  expect_failures = [var.ingress]
}

# Keys are day2's reference_key: SHA-256 of {"id":...,"revision":...}. The
# literals were computed outside OpenTofu so a change in encoding fails here.
run "provisions_outbound_and_verification_secrets_from_exact_versions" {
  command = plan
  variables {
    resource_catalog = {
      version = 1
      connections = {
        forge = {
          revision = 1
          provider = "gitea_actions"
          live = {
            provider           = "gitea_actions"
            endpoint           = "https://git.example.com"
            credential_ref     = { id = "forge-token", revision = 1 }
            signing_secret_ref = { id = "forge-signer", revision = 1 }
          }
        }
        # A second provider shape: the catalog is a tuple of unlike objects.
        alerts = {
          revision = 1
          provider = "slack_webhook"
          live = {
            provider       = "slack_webhook"
            credential_ref = { id = "alerts-webhook", revision = 1 }
          }
        }
      }
      resources = {}
      policies  = {}
    }
    ingress             = { gitea = { actor = "owner@example.com", connection = { id = "forge", revision = 1 } } }
    credential_operator = "operator@example.com"
    provider_credentials = [
      {
        credential_ref = { id = "forge-token", revision = 1 }
        secret_version = "projects/example-tools/secrets/forge-token/versions/3"
        fingerprint    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      },
      {
        credential_ref = { id = "forge-signer", revision = 1 }
        secret_version = "projects/example-tools/secrets/forge-signer/versions/1"
        fingerprint    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
      },
    ]
  }

  assert {
    condition = (
      jsondecode(kubernetes_config_map_v1.credentials[0].data["credential-a5a7f32250a55cfbb38de1f5486d175644a40d22f95411b6acd303ca29c08d4c.json"]) == {
        connection           = { provider = "gitea_actions", endpoint = "https://git.example.com", credential_ref = { id = "forge-token", revision = 1 }, signing_secret_ref = { id = "forge-signer", revision = 1 } }
        credential_file      = "/run/day2/credentials/a5a7f32250a55cfbb38de1f5486d175644a40d22f95411b6acd303ca29c08d4c"
        expected_fingerprint = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      } &&
      jsondecode(kubernetes_config_map_v1.credentials[0].data["credential-51af0efaac59f9189aad4f7e27487636512661c49b0b7d003e22971c8a7c2602.json"]).reference == { id = "forge-signer", revision = 1 }
    )
    error_message = "The outbound token mounts without a reference; the signing secret names its own."
  }

  assert {
    condition = (
      jsondecode(kubernetes_config_map_v1.credentials[0].data["provisioning.json"]).instance_digest == "sha256:${sha256(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"])}" &&
      alltrue([for pin in jsondecode(kubernetes_config_map_v1.credentials[0].data["provisioning.json"]).inputs :
      pin.digest == "sha256:${sha256(kubernetes_config_map_v1.credentials[0].data[pin.file])}"]) &&
      jsondecode(kubernetes_config_map_v1.credentials[0].data["operator-instance.json"]).control == {
        version = 1, state_directory = "/srv/day2/.state/operator-control", operators = ["operator@example.com"], sources = {}, apps = {}
      } &&
      !can(jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).control)
    )
    error_message = "The plan must pin the exact operator-only instance and inputs; the serving instance has no control section."
  }

  assert {
    condition = (
      yamldecode(kubernetes_manifest.credentials[0].manifest.spec.parameters.secrets) == [
        { resourceName = "projects/example-tools/secrets/forge-token/versions/3", path = "a5a7f32250a55cfbb38de1f5486d175644a40d22f95411b6acd303ca29c08d4c" },
        { resourceName = "projects/example-tools/secrets/forge-signer/versions/1", path = "51af0efaac59f9189aad4f7e27487636512661c49b0b7d003e22971c8a7c2602" },
      ] &&
      kubernetes_manifest.credentials[0].manifest.spec.provider == "gke"
    )
    error_message = "The CSI add-on must read exactly the named versions."
  }

  assert {
    condition = (
      [for init in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container : init.name] == ["state-ownership", "credential-files", "credential-registration"] &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[1].security_context[0].capabilities[0].add == tolist(["CHOWN", "FOWNER"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[1].command == tolist(["/busybox/install", "-o", "10001", "-g", "10001", "-m", "0400", "-t", "/run/day2/credentials",
        "/run/day2/credential-sources/a5a7f32250a55cfbb38de1f5486d175644a40d22f95411b6acd303ca29c08d4c",
      "/run/day2/credential-sources/51af0efaac59f9189aad4f7e27487636512661c49b0b7d003e22971c8a7c2602"]) &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[2].image == var.image &&
      kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[2].args == tolist(["/srv/day2/operator-instance.json", "example_app", "operator@example.com", "/srv/day2/provisioning.json"]) &&
      try(length(kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[2].security_context[0].capabilities[0].add), 0) == 0 &&
      alltrue([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container[2].volume_mount :
      mount.sub_path != "" if mount.name == "credential-metadata"]) &&
      anytrue([for mount in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].container[0].volume_mount :
      mount.name == "credentials" && mount.mount_path == "/run/day2/credentials" && mount.read_only])
    )
    error_message = "Credentials are copied as root with CHOWN and FOWNER only, registered by the runtime image as 10001 from regular files, and mounted read-only into day2."
  }
}

run "renders_no_credential_machinery_without_credentials" {
  command = plan

  assert {
    condition = (
      length(kubernetes_config_map_v1.credentials) == 0 && length(kubernetes_manifest.credentials) == 0 &&
      [for init in kubernetes_stateful_set_v1.day2.spec[0].template[0].spec[0].init_container : init.name] == ["state-ownership"] &&
      !contains(keys(kubernetes_stateful_set_v1.day2.spec[0].template[0].metadata[0].annotations), "day2.dev/credentials-sha256")
    )
    error_message = "An app without provider credentials must render exactly as before."
  }
}

run "refuses_a_floating_secret_version" {
  command = plan
  variables {
    provider_credentials = [{
      credential_ref = { id = "forge-token", revision = 1 }
      secret_version = "projects/example-tools/secrets/forge-token/versions/latest"
      fingerprint    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }]
  }
  expect_failures = [var.provider_credentials]
}

run "refuses_a_credential_no_connection_declares" {
  command = plan
  variables {
    resource_catalog = {
      version     = 1
      connections = {}
      resources   = {}
      policies    = {}
    }
    credential_operator = "operator@example.com"
    provider_credentials = [{
      credential_ref = { id = "stray", revision = 1 }
      secret_version = "projects/example-tools/secrets/stray/versions/1"
      fingerprint    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }]
  }
  expect_failures = [kubernetes_config_map_v1.credentials]
}

run "renders_journal_trace_retention_only_when_set" {
  command = plan
  variables {
    journal_trace_hours = 2
  }
  assert {
    condition     = jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.journal == { trace_hours = 2 }
    error_message = "journal_trace_hours must render as the app's journal policy."
  }
}

run "omits_journal_policy_by_default" {
  command = plan
  assert {
    condition     = !can(jsondecode(kubernetes_config_map_v1.instance.data["instance.json"]).apps.example_app.journal)
    error_message = "Without journal_trace_hours the app keeps day2's default retention."
  }
}

run "refuses_fractional_trace_retention" {
  command = plan
  variables {
    journal_trace_hours = 1.5
  }
  expect_failures = [var.journal_trace_hours]
}
