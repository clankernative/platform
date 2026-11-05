# Ordinary, compatible SQLite releases share one node and one retained RWO PVC.
# StatefulSet/native storage remains a separate explicitly exclusive profile.
variable "rolling_deploys" {
  type        = bool
  default     = false
  description = "Use the ordinary SQLite same-node rolling profile. Install on an empty workload or perform a separately reviewed controller handoff; release through maintain rollout."
}

moved {
  from = kubernetes_stateful_set_v1.day2
  to   = kubernetes_stateful_set_v1.day2[0]
}

data "kubernetes_resources" "exclusive_workload" {
  count          = var.rolling_deploys ? 1 : 0
  api_version    = "apps/v1"
  kind           = "StatefulSet"
  namespace      = var.namespace
  field_selector = "metadata.name=${local.workload_name}"
}

resource "terraform_data" "rolling_admission" {
  lifecycle {
    precondition {
      condition     = !var.rolling_deploys || (var.native_enrollment_placement == null && var.oauth_instance_json == null && length(var.loopback_services) == 0 && var.app_calls == null)
      error_message = "Rolling v1 is an ordinary single-store workload; native storage, OAuth, app-call release bindings and mutable companion services require their separate release protocols."
    }
    precondition {
      condition     = !var.rolling_deploys || length(try(data.kubernetes_resources.exclusive_workload[0].objects, [])) == 0
      error_message = "An exclusive StatefulSet still exists. Do not switch controllers through an ordinary apply; preserve its PVC and perform the separately reviewed bootstrap handoff first."
    }
    precondition {
      condition     = !var.rolling_deploys || var.release_managed || local.live == null || local.live_image == var.image || local.activated_image == var.image
      error_message = "Use day2 platform maintain rollout for a compatible image change, then enable release_managed to retain the released software during infrastructure reconciliation."
    }
  }
}

resource "kubernetes_deployment_v1" "rolling" {
  count      = var.rolling_deploys ? 1 : 0
  depends_on = [terraform_data.release_admission, terraform_data.rolling_admission]
  metadata {
    name        = local.workload_name
    namespace   = var.namespace
    labels      = local.pod_labels
    annotations = merge(local.app_call_annotations, var.release_managed ? { "day2.dev/artifact" = local.release_artifact } : {}, local.release_annotations)
  }

  spec {
    replicas                  = local.replicas
    min_ready_seconds         = 10
    progress_deadline_seconds = 600
    revision_history_limit    = 3

    selector {
      match_labels = local.selector_labels
    }

    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    template {
      metadata {
        labels = merge(local.pod_labels, var.release_managed ? {
          for key, value in try(local.released.spec.template.metadata.labels, {}) : key => value if key == "day2.dev/rollout"
        } : {})
        annotations = merge({
          "day2.dev/installation" = var.installation
          "day2.dev/environment"  = var.environment
          "day2.dev/app"          = var.app_id
          "day2.dev/artifact"     = "sha256:${var.artifact_id}"
          # subPath mounts do not follow ConfigMap updates; roll the pod instead.
          "day2.dev/instance-sha256" = sha256(local.instance_json)
          }, local.has_credentials ? {
          "day2.dev/credentials-sha256" = sha256(local.provisioning_plan_json)
          } : {}, length(local.loopback_services) == 0 ? {} : {
          "day2.dev/loopback-services-sha256" = sha256(jsonencode(var.loopback_services))
        }, var.app_calls == null ? {} : { "day2.dev/app-calls-sha256" = sha256(jsonencode(local.app_call_config)) }, local.release_template_annotations)
      }

      spec {
        # Ordinary App mode needs no Kubernetes API token. Native epoch reads
        # project only their explicit API/subject tokens below; automount stays off.
        service_account_name             = var.service_account_name
        automount_service_account_token  = false
        enable_service_links             = false
        termination_grace_period_seconds = var.runtime_resources.shutdown_seconds + 45

        affinity {
          pod_affinity {
            required_during_scheduling_ignored_during_execution {
              topology_key = "kubernetes.io/hostname"
              label_selector { match_labels = { "app.kubernetes.io/name" = local.workload_name, "day2.dev/state-claim" = local.pvc_name } }
            }
          }
        }

        host_pid      = var.native_enrollment_placement != null
        host_network  = false
        host_ipc      = false
        node_selector = merge(var.node_selector, local.native_node_selector)

        dynamic "toleration" {
          for_each = var.native_enrollment_placement == null ? [] : [var.native_enrollment_placement]
          content {
            key      = "day2.dev/native-enrollment"
            operator = "Equal"
            value    = toleration.value.profile
            effect   = "NoSchedule"
          }
        }

        # No fsGroup on purpose: kubelet's fsGroup handling would re-add group
        # rwx and setgid to the state directory day2 keeps at 0700.
        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        dynamic "init_container" {
          # Native storage already has its actual Controller-owned metadata.
          # No startup chown may change that original mount/root observation.
          for_each = var.state_ownership_init_enabled && !local.native_enabled ? [true] : []

          content {
            name              = "state-ownership"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            # The app image is distroless and has no shell, so this runs in a
            # separate pinned image that carries busybox. Only chown: CAP_CHOWN
            # permits it whoever owns the directory, so it is idempotent on
            # every later start. day2 chmods .state to 0700 itself as its
            # owner. (A chmod here would need CAP_FOWNER once the directory is
            # 10001's, and failed every start after the first.)
            command = ["/busybox/chown", "10001:10001", local.state_dir]

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false

              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN"]
              }

              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            resources {
              requests = {
                cpu               = "50m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
              limits = {
                cpu               = "100m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
            }

            volume_mount {
              name       = "state"
              mount_path = local.state_dir
            }
          }
        }

        # See credentials.tf. BusyBox install sets the owner before the mode,
        # so changing the mode of the now-10001-owned file needs CAP_FOWNER.
        dynamic "init_container" {
          for_each = var.app_calls == null ? [] : [true]
          content {
            name    = "app-call-key-files"
            image   = var.state_ownership_image
            command = ["/busybox/install", "-o", "10001", "-g", "10001", "-m", "0400", "-t", "${local.app_call_dir}/keys", "${local.app_call_dir}/sources/issuer", "${local.app_call_dir}/sources/workload"]
            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN", "FOWNER"]
              }
              seccomp_profile { type = "RuntimeDefault" }
            }
            resources {
              requests = { cpu = "50m", memory = "32Mi", ephemeral-storage = "16Mi" }
              limits   = { cpu = "100m", memory = "32Mi", ephemeral-storage = "16Mi" }
            }
            volume_mount {
              name       = "app-call-key-sources"
              mount_path = "${local.app_call_dir}/sources"
              read_only  = true
            }
            volume_mount {
              name       = "app-call-keys"
              mount_path = "${local.app_call_dir}/keys"
            }
          }
        }

        dynamic "init_container" {
          for_each = local.has_credentials ? [true] : []

          content {
            name              = "credential-files"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            # A release-managed workload keeps the released files (release.tf).
            command = var.release_managed ? local.release_credential_files : concat(
              ["/busybox/install", "-o", "10001", "-g", "10001", "-m", "0400", "-t", local.credential_dir],
              [for credential in local.credentials : "${local.credential_source_dir}/${credential.key}"],
            )

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false

              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN", "FOWNER"]
              }

              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            resources {
              requests = {
                cpu               = "50m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
              limits = {
                cpu               = "100m"
                memory            = "32Mi"
                ephemeral-storage = "16Mi"
              }
            }

            volume_mount {
              name       = "credential-sources"
              mount_path = local.credential_source_dir
              read_only  = true
            }

            volume_mount {
              name       = "credentials"
              mount_path = local.credential_dir
            }
          }
        }

        dynamic "init_container" {
          for_each = length(local.loopback_services) == 0 ? [] : [true]

          content {
            name              = "loopback-service-config-files"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            command = concat(
              ["/busybox/install", "-o", "10001", "-g", "10001", "-m", "0600", "-t", local.loopback_config_dir],
              [for name in sort(keys(local.loopback_services)) : "${local.loopback_source_dir}/${name}.json"],
            )

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false
              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN", "FOWNER"]
              }
              seccomp_profile { type = "RuntimeDefault" }
            }

            resources {
              requests = { cpu = "50m", memory = "32Mi", ephemeral-storage = "16Mi" }
              limits   = { cpu = "100m", memory = "32Mi", ephemeral-storage = "16Mi" }
            }

            volume_mount {
              name       = "loopback-config-sources"
              mount_path = local.loopback_source_dir
              read_only  = true
            }
            volume_mount {
              name       = "loopback-service-configs"
              mount_path = local.loopback_config_dir
            }
          }
        }

        dynamic "init_container" {
          for_each = local.loopback_services

          content {
            name              = "loopback-state-${init_container.key}"
            image             = var.state_ownership_image
            image_pull_policy = "IfNotPresent"
            command           = ["/busybox/chown", "10001:10001", "/loopback-state"]

            security_context {
              run_as_non_root            = false
              run_as_user                = 0
              run_as_group               = 0
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false
              capabilities {
                drop = ["ALL"]
                add  = ["CHOWN"]
              }
              seccomp_profile { type = "RuntimeDefault" }
            }

            resources {
              requests = { cpu = "50m", memory = "32Mi", ephemeral-storage = "16Mi" }
              limits   = { cpu = "100m", memory = "32Mi", ephemeral-storage = "16Mi" }
            }

            volume_mount {
              name       = "state"
              mount_path = "/loopback-state"
              sub_path   = init_container.value.state_subpath
            }
          }
        }

        dynamic "init_container" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credential-registration"
            # The released artifact is baked into the released image only.
            image             = var.release_managed ? local.release_credential_image : var.image
            image_pull_policy = "IfNotPresent"
            command           = ["/usr/local/bin/day2-provision-credentials"]
            args              = local.credential_registration_args

            security_context {
              run_as_non_root            = true
              run_as_user                = 10001
              run_as_group               = 10001
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false

              capabilities {
                drop = ["ALL"]
              }

              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            resources {
              requests = local.container_limits
              limits   = local.container_limits
            }

            # Every input is a regular file (subPath): provisioning refuses
            # symlinks, which a ConfigMap directory mount would present.
            volume_mount {
              name       = "credential-metadata"
              mount_path = local.operator_instance
              sub_path   = "operator-instance.json"
              read_only  = true
            }

            volume_mount {
              name       = "credential-metadata"
              mount_path = local.provisioning_plan
              sub_path   = "provisioning.json"
              read_only  = true
            }

            dynamic "volume_mount" {
              for_each = keys(local.provisioning_inputs)

              content {
                name       = "credential-metadata"
                mount_path = "${local.provisioning_dir}/${volume_mount.value}"
                sub_path   = volume_mount.value
                read_only  = true
              }
            }

            volume_mount {
              name       = "credentials"
              mount_path = local.credential_dir
              read_only  = true
            }

            volume_mount {
              name       = "state"
              mount_path = local.state_dir
            }

            volume_mount {
              name       = "tmp"
              mount_path = "/tmp"
            }
          }
        }

        container {
          name              = "day2"
          image             = local.release_image
          image_pull_policy = "IfNotPresent"
          dynamic "volume_mount" {
            for_each = var.native_enrollment_placement == null ? [] : [true]
            content {
              name       = "native-enrollment"
              mount_path = "/run/day2-native-enrollment"
              read_only  = true
            }
          }
          command = ["/usr/local/bin/day2-serve"]
          args    = concat([local.instance_path, var.app_id, "--edge"], var.app_calls == null ? [] : ["--app-calls", "${local.app_call_dir}/host.json"])
          env {
            name  = "DAY2_EXPECTED_ARTIFACT"
            value = local.release_artifact
          }
          dynamic "volume_mount" {
            for_each = var.app_calls == null ? {} : {
              host      = { name = "app-call-config", path = "${local.app_call_dir}/host.json", sub_path = "host.json" }
              selection = { name = "app-call-selection", path = "${local.app_call_dir}/selection", sub_path = null }
              keys      = { name = "app-call-keys", path = "${local.app_call_dir}/keys", sub_path = null }
            }
            content {
              name       = volume_mount.value.name
              mount_path = volume_mount.value.path
              sub_path   = volume_mount.value.sub_path
              read_only  = true
            }
          }

          port {
            name           = "http"
            container_port = 8080
            protocol       = "TCP"
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 10001
            run_as_group               = 10001
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            privileged                 = false

            capabilities {
              drop = ["ALL"]
            }

            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          resources {
            requests = local.container_limits
            limits   = local.container_limits
          }

          # The instance must be a regular file on a read-only mount (a
          # ConfigMap directory mount would be a symlink), hence subPath.
          volume_mount {
            name       = "instance"
            mount_path = local.instance_path
            sub_path   = "instance.json"
            read_only  = true
          }

          volume_mount {
            name       = "state"
            mount_path = local.state_dir
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          dynamic "volume_mount" {
            for_each = local.native_mounts
            content {
              name       = volume_mount.value.name
              mount_path = volume_mount.value.path
              sub_path   = volume_mount.value.sub_path
              read_only  = volume_mount.value.read_only
            }
          }

          # The registered mounts' paths; see credentials.tf.
          dynamic "volume_mount" {
            for_each = local.has_credentials ? [true] : []

            content {
              name       = "credentials"
              mount_path = local.credential_dir
              read_only  = true
            }
          }

          # /srv/day2/artifacts/<artifact_id> is baked into the image and read-only
          # through readOnlyRootFilesystem; no volume may be mounted under it.

          lifecycle {
            pre_stop {
              exec {
                command = ["/usr/local/bin/day2-health", "8080", "--drain-delay"]
              }
            }
          }

          dynamic "env" {
            for_each = var.release_managed && try(local.released.metadata.annotations["day2.dev/rollout"], "") != "" ? [local.released.metadata.annotations["day2.dev/rollout"]] : []
            content {
              name  = "DAY2_EXPECTED_ROLLOUT"
              value = env.value
            }
          }

          readiness_probe {
            http_get {
              path = "/health/ready"
              port = "http"
            }
            period_seconds    = 5
            timeout_seconds   = 2
            failure_threshold = 3
          }

          dynamic "liveness_probe" {
            for_each = local.native_enabled ? [] : [true]
            content {
              http_get {
                path = "/health/live"
                port = "http"
              }
              initial_delay_seconds = 10
              period_seconds        = 10
              timeout_seconds       = 2
              failure_threshold     = 6
            }
          }
        }

        dynamic "container" {
          for_each = local.loopback_services
          content {
            name              = container.key
            image             = container.value.image
            image_pull_policy = "IfNotPresent"
            args              = ["serve", local.loopback_config_path]

            port {
              name           = container.key
              container_port = container.value.port
              protocol       = "TCP"
            }

            security_context {
              run_as_non_root            = true
              run_as_user                = 10001
              run_as_group               = 10001
              allow_privilege_escalation = false
              read_only_root_filesystem  = true
              privileged                 = false
              capabilities {
                drop = ["ALL"]
              }
              seccomp_profile { type = "RuntimeDefault" }
            }

            resources {
              requests = {
                cpu               = "${container.value.resources.cpu_millis}m"
                memory            = "${container.value.resources.memory_mib}Mi"
                ephemeral-storage = "64Mi"
              }
              limits = {
                cpu               = "${container.value.resources.cpu_millis}m"
                memory            = "${container.value.resources.memory_mib}Mi"
                ephemeral-storage = "64Mi"
              }
            }

            volume_mount {
              name       = "loopback-service-configs"
              mount_path = local.loopback_config_path
              sub_path   = container.value.config_key
              read_only  = true
            }
            volume_mount {
              name       = "state"
              mount_path = "/var/lib/day2/loopback-state"
              sub_path   = container.value.state_subpath
            }

            liveness_probe {
              exec {
                command = concat(
                  container.value.health_check.command,
                  ["http://127.0.0.1:${container.value.port}${container.value.health_check.path}"],
                )
              }
              initial_delay_seconds = 10
              period_seconds        = 10
              timeout_seconds       = 2
              failure_threshold     = 3
            }
          }
        }

        volume {
          name = "instance"

          config_map {
            name         = local.release_instance
            default_mode = "0444"

            items {
              key  = "instance.json"
              path = "instance.json"
            }
          }
        }

        volume {
          name = "state"

          persistent_volume_claim {
            claim_name = local.pvc_name
          }
        }

        dynamic "volume" {
          for_each = local.native_enabled ? [true] : []
          content {
            name = "native-policy"
            config_map {
              name         = kubernetes_config_map_v1.native_policy[0].metadata[0].name
              default_mode = "0444"
            }
          }
        }
        dynamic "volume" {
          for_each = local.native_enabled ? [true] : []
          content {
            name = "native-api"
            projected {
              default_mode = "0444"
              sources {
                service_account_token {
                  path               = "token"
                  expiration_seconds = 3600
                }
              }
              sources {
                config_map {
                  name = "kube-root-ca.crt"
                  items {
                    key  = "ca.crt"
                    path = "ca.crt"
                  }
                }
              }
            }
          }
        }
        dynamic "volume" {
          for_each = local.native_enabled ? [true] : []
          content {
            name = "native-subject"
            projected {
              default_mode = "0444"
              sources {
                service_account_token {
                  path               = "subject-token"
                  audience           = try(local.native_role.token_review_audience, "")
                  expiration_seconds = 600
                }
              }
            }
          }
        }

        volume {
          name = "tmp"

          empty_dir {
            medium     = "Memory"
            size_limit = var.tmp_size_limit
          }
        }
        dynamic "volume" {
          for_each = var.app_calls == null ? {} : {
            config    = { name = "app-call-config", config_map = kubernetes_config_map_v1.app_calls[0].metadata[0].name }
            selection = { name = "app-call-selection", config_map = var.app_calls.serving_snapshot_config_map }
          }
          content {
            name = volume.value.name
            config_map {
              name         = volume.value.config_map
              default_mode = "0444"
              optional     = volume.key == "selection"
            }
          }
        }
        dynamic "volume" {
          for_each = var.app_calls == null ? [] : [true]
          content {
            name = "app-call-key-sources"
            csi {
              driver            = "secrets-store-gke.csi.k8s.io"
              read_only         = true
              volume_attributes = { secretProviderClass = kubernetes_manifest.app_call_keys[0].manifest.metadata.name }
            }
          }
        }
        dynamic "volume" {
          for_each = var.app_calls == null ? [] : [true]
          content {
            name = "app-call-keys"
            empty_dir {
              medium     = "Memory"
              size_limit = "1Mi"
            }
          }
        }

        dynamic "volume" {
          for_each = var.native_enrollment_placement == null ? [] : [true]
          content {
            name = "native-enrollment"
            host_path {
              path = "/run/day2-native-enrollment"
              type = "Directory"
            }
          }
        }
        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credential-sources"

            csi {
              driver    = "secrets-store-gke.csi.k8s.io"
              read_only = true
              volume_attributes = {
                secretProviderClass = kubernetes_manifest.credentials[0].manifest.metadata.name
              }
            }
          }
        }

        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credentials"

            empty_dir {
              medium     = "Memory"
              size_limit = "1Mi"
            }
          }
        }

        dynamic "volume" {
          for_each = length(local.loopback_services) == 0 ? [] : [true]
          content {
            name = "loopback-config-sources"
            csi {
              driver    = "secrets-store-gke.csi.k8s.io"
              read_only = true
              volume_attributes = {
                secretProviderClass = kubernetes_manifest.loopback_service_secrets[0].manifest.metadata.name
              }
            }
          }
        }

        dynamic "volume" {
          for_each = length(local.loopback_services) == 0 ? [] : [true]
          content {
            name = "loopback-service-configs"
            empty_dir {
              medium     = "Memory"
              size_limit = "4Mi"
            }
          }
        }

        dynamic "volume" {
          for_each = local.has_credentials ? [true] : []

          content {
            name = "credential-metadata"

            # Derived from the released instance; the bootstrap ConfigMap
            # serves only until the first release.
            config_map {
              name         = var.release_managed ? local.release_credential_metadata : kubernetes_config_map_v1.credentials[0].metadata[0].name
              default_mode = "0444"
            }
          }
        }
      }
    }
  }

  timeouts {
    create = "15m"
    update = "15m"
  }
}
