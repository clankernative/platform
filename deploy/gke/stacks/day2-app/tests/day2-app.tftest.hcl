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
          auditors  = []
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
