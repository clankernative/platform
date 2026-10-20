locals {
  profile_name = "day2-native-enrollment"
  policy = templatefile("${path.module}/../native-enrollment-pool/apparmor/day2-native-enrollment.tftpl", {
    client_executables = join(" ", sort(tolist(var.client_executable_paths)))
  })
  policy_hash  = sha256(local.policy)
  loader       = "/node/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
  library_path = "/node/usr/lib/x86_64-linux-gnu"
}

resource "kubernetes_namespace_v1" "profiles" {
  metadata { name = var.namespace }
}

resource "kubernetes_config_map_v1" "policy" {
  metadata {
    name      = "native-enrollment-${substr(local.policy_hash, 0, 16)}"
    namespace = kubernetes_namespace_v1.profiles.metadata[0].name
  }
  immutable = true
  data      = { (local.profile_name) = local.policy }
  lifecycle { create_before_destroy = true }
}

locals {
  loader_spec = {
    selector       = { matchLabels = { app = "native-enrollment-apparmor" } }
    updateStrategy = { type = "RollingUpdate", rollingUpdate = { maxUnavailable = 1 } }
    template = {
      metadata = {
        labels      = { app = "native-enrollment-apparmor" }
        annotations = { "day2.dev/apparmor-policy" = local.policy_hash }
      }
      spec = {
        automountServiceAccountToken = false
        # Omit default-false host namespaces: the Kubernetes API removes
        # these zero-valued fields from its canonical object representation.
        nodeSelector = {
          "cloud.google.com/gke-nodepool"                      = var.pool_name
          "day2.dev.node-restriction.kubernetes.io/enrollment" = var.profile
          "kubernetes.io/arch"                                 = "amd64"
        }
        tolerations = [{
          key   = "day2.dev/native-enrollment", operator = "Equal",
          value = var.profile, effect = "NoSchedule"
        }]
        initContainers = [{
          name    = "load"
          image   = var.loader_image
          command = [local.loader, "--library-path", local.library_path, "/node/usr/sbin/apparmor_parser"]
          args    = ["--config-file", "/dev/null", "--replace", "--skip-cache", "--subdomainfs", "/apparmor", "/profiles/${local.profile_name}"]
          securityContext = {
            runAsUser                = 0, runAsGroup = 0,
            allowPrivilegeEscalation = false, readOnlyRootFilesystem = true,
            capabilities             = { drop = ["ALL"], add = ["MAC_ADMIN"] },
            appArmorProfile          = { type = "RuntimeDefault" }
          }
          resources = {
            requests = { cpu = "10m", memory = "32Mi" },
            limits   = { cpu = "100m", memory = "64Mi" }
          }
          volumeMounts = [
            { name = "apparmor", mountPath = "/apparmor" },
            { name = "node-usr", mountPath = "/node/usr", readOnly = true },
            { name = "policy", mountPath = "/profiles", readOnly = true }
          ]
        }]
        containers = [{
          name    = "loaded"
          image   = var.loader_image
          command = [local.loader, "--library-path", local.library_path, "/node/usr/bin/sleep", "infinity"]
          securityContext = {
            # Kernel policy-list visibility requires UID0, not MAC_ADMIN.
            runAsUser                = 0, runAsGroup = 0,
            allowPrivilegeEscalation = false, readOnlyRootFilesystem = true,
            capabilities             = { drop = ["ALL"] },
            appArmorProfile          = { type = "RuntimeDefault" }
          }
          resources = {
            requests = { cpu = "5m", memory = "8Mi" },
            limits   = { cpu = "50m", memory = "16Mi" }
          }
          readinessProbe = {
            exec = { command = [
              local.loader, "--library-path", local.library_path, "/node/usr/bin/grep",
              "-Fqx", "${local.profile_name} (enforce)", "/apparmor/profiles"
            ] }
            periodSeconds = 10, timeoutSeconds = 2
          }
          volumeMounts = [
            { name = "apparmor", mountPath = "/apparmor", readOnly = true },
            { name = "node-usr", mountPath = "/node/usr", readOnly = true }
          ]
        }]
        volumes = [
          { name = "apparmor", hostPath = { path = "/sys/kernel/security/apparmor", type = "Directory" } },
          { name = "node-usr", hostPath = { path = "/usr", type = "Directory" } },
          { name = "policy", configMap = { name = kubernetes_config_map_v1.policy.metadata[0].name } }
        ]
      }
    }
  }
}

resource "kubernetes_manifest" "loader" {
  # The DaemonSet controller updates its own template-generation annotation.
  # Pod-template annotations (including our policy selection) remain managed.
  computed_fields = ["metadata.annotations"]
  manifest = {
    apiVersion = "apps/v1"
    kind       = "DaemonSet"
    metadata = {
      name      = "native-enrollment-apparmor"
      namespace = var.namespace
      # A real spec change must mark controller annotations unknown on update.
      annotations = { "day2.dev/loader-configuration" = sha256(jsonencode(local.loader_spec)) }
    }
    spec = local.loader_spec
  }
  field_manager { name = "day2-native-enrollment-profile" }
  wait {
    rollout = true
  }
  timeouts {
    create = "5m"
    update = "5m"
    delete = "5m"
  }
  depends_on = [kubernetes_namespace_v1.profiles]
}

output "apparmor_profile" {
  value = { type = "Localhost", localhostProfile = local.profile_name }
}
