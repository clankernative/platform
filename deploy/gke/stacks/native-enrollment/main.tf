locals {
  namespace  = "day2-native-enrollment"
  policy     = jsondecode(var.policy_json)
  roles      = [local.policy.bootstrap.app, local.policy.bootstrap.shell, local.policy.bootstrap.controller]
  namespaces = toset([for role in local.roles : role.namespace.name])
}

resource "kubernetes_namespace_v1" "enrollment" {
  metadata { name = local.namespace }
}

# This exact KSA is the previously approved KMS principal. The root signer and
# separate observer IAM remain instance-owned; this stack grants neither.
resource "kubernetes_service_account_v1" "provisioner" {
  metadata {
    name      = "provisioner"
    namespace = kubernetes_namespace_v1.enrollment.metadata[0].name
  }
}

resource "kubernetes_config_map_v1" "policy" {
  metadata {
    name      = "native-enrollment-${substr(sha256(var.policy_json), 0, 16)}"
    namespace = kubernetes_namespace_v1.enrollment.metadata[0].name
  }
  immutable = true
  data      = { "native-enrollment.json" = var.policy_json }
  lifecycle { create_before_destroy = true }
}

resource "kubernetes_cluster_role_v1" "observer" {
  metadata { name = "day2-native-enrollment-observer" }
  rule {
    api_groups     = [""]
    resources      = ["namespaces"]
    resource_names = sort(tolist(local.namespaces))
    verbs          = ["get"]
  }
  rule {
    api_groups     = [""]
    resources      = ["nodes"]
    resource_names = [local.policy.runtime.node_name]
    verbs          = ["get"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "observer" {
  metadata { name = "day2-native-enrollment-observer" }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.observer.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.provisioner.metadata[0].name
    namespace = local.namespace
  }
}

resource "kubernetes_role_v1" "observer" {
  for_each = local.namespaces
  metadata {
    name      = "day2-native-enrollment-observer"
    namespace = each.key
  }
  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["get"]
  }
  rule {
    api_groups     = [""]
    resources      = ["serviceaccounts"]
    resource_names = sort([for role in local.roles : role.kubernetes_service_account.name if role.namespace.name == each.key])
    verbs          = ["get"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["replicasets"]
    verbs      = ["get"]
  }
  rule {
    api_groups     = ["apps"]
    resources      = ["deployments", "statefulsets"]
    resource_names = sort([for role in local.roles : role.workload.name if role.namespace.name == each.key])
    verbs          = ["get"]
  }
  depends_on = [kubernetes_namespace_v1.enrollment]
}

resource "kubernetes_role_binding_v1" "observer" {
  for_each = local.namespaces
  metadata {
    name      = "day2-native-enrollment-observer"
    namespace = each.key
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.observer[each.key].metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.provisioner.metadata[0].name
    namespace = local.namespace
  }
}

resource "kubernetes_manifest" "issuer" {
  manifest = {
    apiVersion = "apps/v1", kind = "Deployment"
    metadata   = { name = "native-enrollment", namespace = local.namespace }
    spec = {
      replicas = 1
      selector = { matchLabels = { app = "native-enrollment" } }
      strategy = { type = "Recreate" }
      template = {
        metadata = { labels = { app = "native-enrollment" } }
        spec = {
          serviceAccountName = kubernetes_service_account_v1.provisioner.metadata[0].name
          hostPID            = true
          nodeSelector = {
            "cloud.google.com/gke-nodepool"                      = var.pool_name
            "day2.dev.node-restriction.kubernetes.io/enrollment" = var.profile
            "kubernetes.io/hostname"                             = local.policy.runtime.node_name
            "kubernetes.io/arch"                                 = "amd64"
          }
          tolerations = [{ key = "day2.dev/native-enrollment", operator = "Equal", value = var.profile, effect = "NoSchedule" }]
          containers = [{
            name    = "provisioner", image = var.image
            command = ["/usr/local/bin/day2-native-enrollment"]
            securityContext = {
              runAsUser                = 0, runAsGroup = 0
              allowPrivilegeEscalation = false, readOnlyRootFilesystem = true
              capabilities             = { drop = ["ALL"], add = ["SYS_PTRACE", "CHOWN"] }
              appArmorProfile          = { type = "Localhost", localhostProfile = "day2-native-enrollment" }
              seccompProfile           = { type = "RuntimeDefault" }
            }
            resources = {
              requests = { cpu = "1", memory = "512Mi" }
              limits   = { cpu = "2", memory = "512Mi" }
            }
            volumeMounts = [
              { name = "policy", mountPath = "/etc/day2/native-enrollment.json", subPath = "native-enrollment.json", readOnly = true },
              { name = "enrollment", mountPath = "/run/day2-native-enrollment" },
              { name = "containerd", mountPath = "/run/containerd", readOnly = true }
            ]
          }]
          volumes = [
            { name = "policy", configMap = { name = kubernetes_config_map_v1.policy.metadata[0].name, defaultMode = 292 } },
            { name = "enrollment", hostPath = { path = "/run/day2-native-enrollment", type = "DirectoryOrCreate" } },
            { name = "containerd", hostPath = { path = "/run/containerd", type = "Directory" } }
          ]
        }
      }
    }
  }
  field_manager { name = "day2-native-enrollment" }
  depends_on = [kubernetes_cluster_role_binding_v1.observer, kubernetes_role_binding_v1.observer]
}

output "policy_config_map" { value = kubernetes_config_map_v1.policy.metadata[0].name }
output "namespace" { value = local.namespace }
