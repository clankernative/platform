# Cluster tenancy for app namespaces (names starting with app_namespace_prefix):
# the Retain-policy StorageClasses and VolumeSnapshotClass that app PVCs use,
# and the ValidatingAdmissionPolicies that keep platform-owned objects in app
# namespaces (ServiceAccounts, RBAC, PVCs, Services, Ingresses, NetworkPolicies,
# platform-contract, the namespace itself) under platform automation, and
# workloads on serviceAccountName=runtime with the required service label.
#
# The day2-app stack's StatefulSet must stay admissible: it uses
# serviceAccountName=runtime, internal-tools.wonderly.io/service=app, and mounts
# the platform PVC (storage class app-sqlite-rwo) instead of volumeClaimTemplates.
#
# Every policy expression below matches the live cluster objects exactly; an
# edit here is an admission change for running app namespaces.
locals {
  sqlite_storage_class_profiles = {
    app-sqlite-rwo = {
      provisioner         = "pd.csi.storage.gke.io"
      reclaim_policy      = "Retain"
      volume_binding_mode = "WaitForFirstConsumer"
      volume_type         = "pd-balanced"
    }
    app-sqlite-hyperdisk-rwo = {
      provisioner         = "pd.csi.storage.gke.io"
      reclaim_policy      = "Retain"
      volume_binding_mode = "WaitForFirstConsumer"
      volume_type         = "hyperdisk-balanced"
    }
  }
  platform_automation_expression = join(" || ", [
    for username in var.platform_automation_usernames :
    "request.userInfo.username == '${username}'"
  ])
  managed_certificate_controller_expression = "request.operation == 'UPDATE' && request.userInfo.username == 'system:managed-certificate-controller'"
  platform_pvc_update_expression = join(" || ", [
    for username in var.platform_pvc_update_usernames :
    "request.userInfo.username == '${username}'"
  ])
  # The upstream snapshot-controller Deployment and RBAC both use the
  # snapshot-controller ServiceAccount in kube-system:
  # https://github.com/kubernetes-csi/external-snapshotter/tree/54c7bf082f33b96411a9f4d6b903b2870332a6f5/deploy/kubernetes/snapshot-controller
  volume_snapshot_controller_pvc_finalizer_update_expression = join(" && ", [
    "request.operation == 'UPDATE'",
    "request.userInfo.username in ['system:serviceaccount:kube-system:snapshot-controller', 'system:snapshot-controller']",
    "object.spec == oldObject.spec",
    "(has(object.metadata.labels) ? object.metadata.labels : {}) == (has(oldObject.metadata.labels) ? oldObject.metadata.labels : {})",
    "(has(object.metadata.annotations) ? object.metadata.annotations : {}) == (has(oldObject.metadata.annotations) ? oldObject.metadata.annotations : {})",
    "(has(object.metadata.ownerReferences) ? object.metadata.ownerReferences : []) == (has(oldObject.metadata.ownerReferences) ? oldObject.metadata.ownerReferences : [])",
    "size((has(object.metadata.finalizers) ? object.metadata.finalizers : []).filter(finalizer, finalizer == 'snapshot.storage.kubernetes.io/pvc-as-source-protection')) <= 1",
    "size((has(oldObject.metadata.finalizers) ? oldObject.metadata.finalizers : []).filter(finalizer, finalizer == 'snapshot.storage.kubernetes.io/pvc-as-source-protection')) <= 1",
    "(has(object.metadata.finalizers) ? object.metadata.finalizers : []).filter(finalizer, finalizer != 'snapshot.storage.kubernetes.io/pvc-as-source-protection') == (has(oldObject.metadata.finalizers) ? oldObject.metadata.finalizers : []).filter(finalizer, finalizer != 'snapshot.storage.kubernetes.io/pvc-as-source-protection')",
  ])
  protected_platform_configmap_name_expression = join(" || ", [
    "(request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name) == 'platform-contract'",
    "(request.operation == 'DELETE' ? oldObject.metadata.name : object.metadata.name) == 'sqlite-backup-script'",
  ])
}

resource "kubernetes_storage_class_v1" "app_sqlite_rwo" {
  metadata {
    name = "app-sqlite-rwo"
    labels = {
      managed_by = "internal-tools-infra"
    }
  }

  storage_provisioner    = local.sqlite_storage_class_profiles["app-sqlite-rwo"].provisioner
  reclaim_policy         = local.sqlite_storage_class_profiles["app-sqlite-rwo"].reclaim_policy
  volume_binding_mode    = local.sqlite_storage_class_profiles["app-sqlite-rwo"].volume_binding_mode
  allow_volume_expansion = true

  parameters = {
    type = local.sqlite_storage_class_profiles["app-sqlite-rwo"].volume_type
  }
}

resource "kubernetes_storage_class_v1" "app_sqlite_hyperdisk_rwo" {
  metadata {
    name = "app-sqlite-hyperdisk-rwo"
    labels = {
      managed_by = "internal-tools-infra"
    }
  }

  storage_provisioner    = local.sqlite_storage_class_profiles["app-sqlite-hyperdisk-rwo"].provisioner
  reclaim_policy         = local.sqlite_storage_class_profiles["app-sqlite-hyperdisk-rwo"].reclaim_policy
  volume_binding_mode    = local.sqlite_storage_class_profiles["app-sqlite-hyperdisk-rwo"].volume_binding_mode
  allow_volume_expansion = true

  parameters = {
    type = local.sqlite_storage_class_profiles["app-sqlite-hyperdisk-rwo"].volume_type
  }
}

resource "kubernetes_manifest" "pd_snapshot_class" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "snapshot.storage.k8s.io/v1"
    kind       = "VolumeSnapshotClass"
    metadata = {
      name = "gke-pd-retain"
      labels = {
        managed_by = "internal-tools-infra"
      }
    }
    driver         = "pd.csi.storage.gke.io"
    deletionPolicy = "Retain"
  }
}

# App workloads run as the platform's "runtime" ServiceAccount. The
# runtime-worker and deploy-smoke alternatives are only narrower exceptions for
# Deployments and Jobs carrying those exact labels; day2 apps use neither. They
# are kept unchanged so this policy matches the live object.
#
# The one day2 exception: Jobs (including those a CronJob creates, whose
# spec.template is the CronJob's jobTemplate) labelled
# internal-tools.wonderly.io/service=backup may use the "backup" ServiceAccount,
# with token automount disabled. app-edge binds that account through Workload
# Identity to a Google service account that may only create objects in the
# app's backup bucket; day2-app's backup CronJob uses it.
resource "kubernetes_manifest" "require_runtime_service_account" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "require-runtime-service-account"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = ["apps"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["deployments", "statefulsets", "daemonsets"]
          },
          {
            apiGroups   = ["batch"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["jobs"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            "has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'runtime' && (object.kind != 'Job' || !has(object.spec.template.metadata.labels) || !('internal-tools.wonderly.io/deploy-smoke' in object.spec.template.metadata.labels) || object.spec.template.metadata.labels['internal-tools.wonderly.io/deploy-smoke'] != 'true')",
            join(" && ", [
              "object.kind == 'Deployment'",
              "has(object.spec.template.spec.serviceAccountName)",
              "object.spec.template.spec.serviceAccountName == 'runtime-worker'",
              "has(object.spec.template.metadata.labels)",
              "'internal-tools.wonderly.io/runtime-role' in object.spec.template.metadata.labels",
              "object.spec.template.metadata.labels['internal-tools.wonderly.io/runtime-role'] == 'notification-worker'",
            ]),
            join(" && ", [
              "object.kind == 'Deployment'",
              "has(object.spec.template.spec.serviceAccountName)",
              "object.spec.template.spec.serviceAccountName == 'runtime-worker'",
              "has(object.spec.template.metadata.labels)",
              "'internal-tools.wonderly.io/runtime-role' in object.spec.template.metadata.labels",
              "object.spec.template.metadata.labels['internal-tools.wonderly.io/runtime-role'] == 'worker'",
              "'internal-tools.wonderly.io/workload-controller' in object.spec.template.metadata.labels",
              "object.spec.template.metadata.labels['internal-tools.wonderly.io/workload-controller'] == 'sqlite-rwo-worker'",
            ]),
            join(" && ", [
              "object.kind == 'Job'",
              "has(object.spec.template.spec.serviceAccountName)",
              "object.spec.template.spec.serviceAccountName == 'smoke'",
              "has(object.spec.template.spec.automountServiceAccountToken)",
              "object.spec.template.spec.automountServiceAccountToken == false",
              "has(object.spec.template.metadata.labels)",
              "'internal-tools.wonderly.io/deploy-smoke' in object.spec.template.metadata.labels",
              "object.spec.template.metadata.labels['internal-tools.wonderly.io/deploy-smoke'] == 'true'",
            ]),
            join(" && ", [
              "object.kind == 'Job'",
              "has(object.spec.template.spec.serviceAccountName)",
              "object.spec.template.spec.serviceAccountName == 'backup'",
              "has(object.spec.template.spec.automountServiceAccountToken)",
              "object.spec.template.spec.automountServiceAccountToken == false",
              "has(object.spec.template.metadata.labels)",
              "'internal-tools.wonderly.io/service' in object.spec.template.metadata.labels",
              "object.spec.template.metadata.labels['internal-tools.wonderly.io/service'] == 'backup'",
            ]),
          ])
          message = "App workloads must use serviceAccountName=runtime; dedicated notification and SQLite worker Deployments may use runtime-worker, isolated deploy-smoke Jobs must use smoke with token automount disabled, and backup Jobs labelled internal-tools.wonderly.io/service=backup may use backup with token automount disabled."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "require_runtime_service_account_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "require-runtime-service-account"
    }
    spec = {
      policyName        = kubernetes_manifest.require_runtime_service_account.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_service_account_changes_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-app-service-account-mutation"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["serviceaccounts"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            local.platform_automation_expression,
          ])
          message = "ServiceAccount objects in app-* namespaces are platform-managed."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_service_account_changes_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-app-service-account-mutation"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_service_account_changes_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_rbac_changes_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-app-rbac-mutation"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = ["rbac.authorization.k8s.io"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["roles", "rolebindings"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            local.platform_automation_expression,
          ])
          message = "RBAC objects in app-* namespaces are platform-managed."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_rbac_changes_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-app-rbac-mutation"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_rbac_changes_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "require_app_service_label" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "require-app-service-label"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = ["apps"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["deployments", "statefulsets", "daemonsets"]
          },
          {
            apiGroups   = ["batch"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["jobs"]
          },
        ]
      }
      validations = [
        {
          expression = join(" ", [
            "!has(request.namespace) || !request.namespace.startsWith('${var.app_namespace_prefix}') ||",
            "(has(object.spec.template.metadata.labels) && (",
            "(('internal-tools.wonderly.io/service' in object.spec.template.metadata.labels) &&",
            "(request.resource.resource == 'jobs' ? ['app', 'backup', 'background'].exists(value, value == object.spec.template.metadata.labels['internal-tools.wonderly.io/service']) :",
            "(object.spec.template.metadata.labels['internal-tools.wonderly.io/service'] == 'app' || object.spec.template.metadata.labels['internal-tools.wonderly.io/service'].matches('^app-[a-z0-9]([a-z0-9-]*[a-z0-9])?$')))) ||",
            "(request.resource.resource != 'jobs' &&",
            "('app.kubernetes.io/component' in object.spec.template.metadata.labels) &&",
            "object.spec.template.metadata.labels['app.kubernetes.io/component'] == 'background')",
            "))",
          ])
          message = "Service workloads must use internal-tools.wonderly.io/service=app or app-<route-service>. Jobs may use service=backup or service=background to remain outside the application Service."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "require_app_service_label_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "require-app-service-label"
    }
    spec = {
      policyName        = kubernetes_manifest.require_app_service_label.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_pvc_deletion_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-app-pvc-delete"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["DELETE"]
            resources   = ["persistentvolumeclaims"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            "request.userInfo.username.startsWith('system:')",
            "(request.namespace in ${jsonencode(var.destructive_teardown_namespaces)} && request.userInfo.username in ${jsonencode(var.platform_automation_usernames)})",
          ])
          message = "PersistentVolumeClaims in app-* namespaces cannot be deleted directly."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_app_namespace_deletion" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-app-namespace-delete"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["DELETE"]
            resources   = ["namespaces"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(oldObject.metadata.name)",
            "!oldObject.metadata.name.startsWith('${var.app_namespace_prefix}')",
            "request.userInfo.username.startsWith('system:')",
            "(oldObject.metadata.name in ${jsonencode(var.destructive_teardown_namespaces)} && request.userInfo.username in ${jsonencode(var.platform_automation_usernames)})",
          ])
          message = "Namespaces named app-* cannot be deleted directly."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_app_namespace_deletion_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-app-namespace-delete"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_app_namespace_deletion.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_pvc_deletion_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-app-pvc-delete"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_statefulset_volume_claim_templates_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-app-statefulset-volume-claim-templates"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = ["apps"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["statefulsets"]
          },
        ]
      }
      validations = [
        {
          expression = join(" && ", [
            "!has(request.namespace) || !request.namespace.startsWith('${var.app_namespace_prefix}') || !has(object.spec.volumeClaimTemplates) || size(object.spec.volumeClaimTemplates) == 0",
            "!has(request.namespace) || !request.namespace.startsWith('${var.app_namespace_prefix}') || !has(object.spec.persistentVolumeClaimRetentionPolicy)",
          ])
          message = "App StatefulSets must mount the platform-managed PVC instead of declaring volumeClaimTemplates or persistentVolumeClaimRetentionPolicy."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_statefulset_volume_claim_templates_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-app-statefulset-volume-claim-templates"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_statefulset_volume_claim_templates_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_platform_pvc_mutation_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-platform-pvc-mutation"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            resources   = ["persistentvolumeclaims"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            local.platform_automation_expression,
            "(request.operation == 'UPDATE' && (${local.platform_pvc_update_expression}))",
            "(${local.volume_snapshot_controller_pvc_finalizer_update_expression})",
          ])
          message = "PersistentVolumeClaims in app-* namespaces are platform-managed; only platform automation, required control-plane updates, and the snapshot controller's source-protection finalizer are allowed."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_platform_pvc_mutation_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-platform-pvc-mutation"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "forbid_platform_resource_mutation_in_app_namespaces" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "forbid-platform-resource-mutation"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["services", "limitranges", "resourcequotas"]
          },
          {
            apiGroups   = ["networking.k8s.io"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["ingresses", "networkpolicies"]
          },
          {
            apiGroups   = ["cloud.google.com"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["backendconfigs"]
          },
          {
            apiGroups   = ["networking.gke.io"]
            apiVersions = ["v1", "v1beta1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["frontendconfigs", "managedcertificates"]
          },
          {
            apiGroups   = ["secrets-store.csi.x-k8s.io"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["secretproviderclasses"]
          },
          {
            apiGroups   = ["batch"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["cronjobs"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            local.managed_certificate_controller_expression,
            local.platform_automation_expression,
          ])
          message = "Ingress, network, storage, resource guardrails, and platform integration resources in app-* namespaces are platform-managed."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "forbid_platform_resource_mutation_in_app_namespaces_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "forbid-platform-resource-mutation"
    }
    spec = {
      policyName        = kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}

resource "kubernetes_manifest" "protect_platform_contract_configmap" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name = "protect-platform-contract-configmap"
    }
    spec = {
      failurePolicy = "Fail"
      matchConstraints = {
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE", "DELETE"]
            resources   = ["configmaps"]
          },
        ]
      }
      validations = [
        {
          expression = join(" || ", [
            "!has(request.namespace)",
            "!request.namespace.startsWith('${var.app_namespace_prefix}')",
            local.platform_automation_expression,
            "!(${local.protected_platform_configmap_name_expression})",
          ])
          message = "ConfigMaps platform-contract and sqlite-backup-script are platform-managed."
        },
      ]
    }
  }
}

resource "kubernetes_manifest" "protect_platform_contract_configmap_binding" {
  field_manager {
    name            = "opentofu"
    force_conflicts = true
  }

  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name = "protect-platform-contract-configmap"
    }
    spec = {
      policyName        = kubernetes_manifest.protect_platform_contract_configmap.manifest.metadata.name
      validationActions = ["Deny"]
    }
  }
}
