# Offline: the kubernetes provider is mocked, so this never contacts a cluster.
mock_provider "kubernetes" {}

variables {
  platform_automation_usernames = [
    "infra-apply@example-project.iam.gserviceaccount.com",
    "operator@example.com",
  ]
}

run "app_pvc_storage_class_retains_and_waits_for_the_pod" {
  command = plan

  assert {
    condition     = output.storage_class_name == "app-sqlite-rwo"
    error_message = "The app PVC storage class must be app-sqlite-rwo (the day2 app's PVC names it)."
  }

  assert {
    condition = (
      kubernetes_storage_class_v1.app_sqlite_rwo.reclaim_policy == "Retain" &&
      kubernetes_storage_class_v1.app_sqlite_rwo.volume_binding_mode == "WaitForFirstConsumer" &&
      kubernetes_storage_class_v1.app_sqlite_rwo.storage_provisioner == "pd.csi.storage.gke.io" &&
      kubernetes_storage_class_v1.app_sqlite_rwo.parameters["type"] == "pd-balanced"
    )
    error_message = "app-sqlite-rwo must be a Retain, WaitForFirstConsumer pd-balanced PD CSI class."
  }

  assert {
    condition     = kubernetes_manifest.pd_snapshot_class.manifest.deletionPolicy == "Retain"
    error_message = "The VolumeSnapshotClass must retain snapshots."
  }
}

run "app_workloads_need_the_runtime_service_account_and_service_label" {
  command = plan

  assert {
    condition = (
      kubernetes_manifest.require_runtime_service_account.manifest.kind == "ValidatingAdmissionPolicy" &&
      kubernetes_manifest.require_runtime_service_account.manifest.spec.failurePolicy == "Fail" &&
      strcontains(kubernetes_manifest.require_runtime_service_account.manifest.spec.validations[0].expression, "!request.namespace.startsWith('app-')") &&
      strcontains(kubernetes_manifest.require_runtime_service_account.manifest.spec.validations[0].expression, "object.spec.template.spec.serviceAccountName == 'runtime'")
    )
    error_message = "require-runtime-service-account must hold app-* workloads to serviceAccountName=runtime."
  }

  assert {
    condition = (
      kubernetes_manifest.require_runtime_service_account_binding.manifest.spec.policyName == "require-runtime-service-account" &&
      kubernetes_manifest.require_runtime_service_account_binding.manifest.spec.validationActions == ["Deny"]
    )
    error_message = "require-runtime-service-account must be bound with Deny."
  }

  assert {
    condition = (
      kubernetes_manifest.require_app_service_label.manifest.spec.failurePolicy == "Fail" &&
      strcontains(kubernetes_manifest.require_app_service_label.manifest.spec.validations[0].expression, "'internal-tools.wonderly.io/service' in object.spec.template.metadata.labels") &&
      strcontains(kubernetes_manifest.require_app_service_label.manifest.spec.validations[0].expression, "object.spec.template.metadata.labels['internal-tools.wonderly.io/service'] == 'app'")
    )
    error_message = "require-app-service-label must require internal-tools.wonderly.io/service=app on app-* workloads."
  }

  assert {
    condition = (
      kubernetes_manifest.require_app_service_label_binding.manifest.spec.policyName == "require-app-service-label" &&
      kubernetes_manifest.require_app_service_label_binding.manifest.spec.validationActions == ["Deny"]
    )
    error_message = "require-app-service-label must be bound with Deny."
  }
}

run "backup_jobs_are_the_one_day2_service_account_exception" {
  command = plan

  assert {
    condition = strcontains(
      kubernetes_manifest.require_runtime_service_account.manifest.spec.validations[0].expression,
      join(" && ", [
        "object.kind == 'Job'",
        "has(object.spec.template.spec.serviceAccountName)",
        "object.spec.template.spec.serviceAccountName == 'backup'",
        "has(object.spec.template.spec.automountServiceAccountToken)",
        "object.spec.template.spec.automountServiceAccountToken == false",
        "has(object.spec.template.metadata.labels)",
        "'internal-tools.wonderly.io/service' in object.spec.template.metadata.labels",
        "object.spec.template.metadata.labels['internal-tools.wonderly.io/service'] == 'backup'",
      ])
    )
    error_message = "The backup service account must be admitted only for Jobs labelled service=backup with token automount disabled."
  }

  # The expression before the exception, verbatim: the backup clause is the
  # only addition, appended as the last alternative.
  assert {
    condition = kubernetes_manifest.require_runtime_service_account.manifest.spec.validations[0].expression == join("", [
      "!has(request.namespace) || !request.namespace.startsWith('app-') || has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'runtime' && (object.kind != 'Job' || !has(object.spec.template.metadata.labels) || !('internal-tools.wonderly.io/deploy-smoke' in object.spec.template.metadata.labels) || object.spec.template.metadata.labels['internal-tools.wonderly.io/deploy-smoke'] != 'true') || object.kind == 'Deployment' && has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'runtime-worker' && has(object.spec.template.metadata.labels) && 'internal-tools.wonderly.io/runtime-role' in object.spec.template.metadata.labels && object.spec.template.metadata.labels['internal-tools.wonderly.io/runtime-role'] == 'notification-worker' || object.kind == 'Deployment' && has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'runtime-worker' && has(object.spec.template.metadata.labels) && 'internal-tools.wonderly.io/runtime-role' in object.spec.template.metadata.labels && object.spec.template.metadata.labels['internal-tools.wonderly.io/runtime-role'] == 'worker' && 'internal-tools.wonderly.io/workload-controller' in object.spec.template.metadata.labels && object.spec.template.metadata.labels['internal-tools.wonderly.io/workload-controller'] == 'sqlite-rwo-worker' || object.kind == 'Job' && has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'smoke' && has(object.spec.template.spec.automountServiceAccountToken) && object.spec.template.spec.automountServiceAccountToken == false && has(object.spec.template.metadata.labels) && 'internal-tools.wonderly.io/deploy-smoke' in object.spec.template.metadata.labels && object.spec.template.metadata.labels['internal-tools.wonderly.io/deploy-smoke'] == 'true'",
      " || object.kind == 'Job' && has(object.spec.template.spec.serviceAccountName) && object.spec.template.spec.serviceAccountName == 'backup' && has(object.spec.template.spec.automountServiceAccountToken) && object.spec.template.spec.automountServiceAccountToken == false && has(object.spec.template.metadata.labels) && 'internal-tools.wonderly.io/service' in object.spec.template.metadata.labels && object.spec.template.metadata.labels['internal-tools.wonderly.io/service'] == 'backup'",
    ])
    error_message = "Apart from the backup Job exception, the runtime, runtime-worker and smoke rules must be unchanged."
  }

  assert {
    condition = (
      strcontains(kubernetes_manifest.require_app_service_label.manifest.spec.validations[0].expression, "request.resource.resource == 'jobs' ? ['app', 'backup', 'background'].exists(") &&
      kubernetes_manifest.require_runtime_service_account.manifest.spec.matchConstraints.resourceRules[1].resources == ["jobs"] &&
      contains(kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces.manifest.spec.matchConstraints.resourceRules[5].resources, "cronjobs")
    )
    error_message = "Backup Jobs must pass the service-label policy; their CronJob stays platform-automation-owned."
  }
}

run "platform_automation_may_change_platform_objects" {
  command = plan

  assert {
    condition = alltrue([
      for policy in [
        kubernetes_manifest.forbid_service_account_changes_in_app_namespaces,
        kubernetes_manifest.forbid_rbac_changes_in_app_namespaces,
        kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces,
        kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces,
        kubernetes_manifest.protect_platform_contract_configmap,
      ] :
      strcontains(policy.manifest.spec.validations[0].expression, "request.userInfo.username == 'infra-apply@example-project.iam.gserviceaccount.com' || request.userInfo.username == 'operator@example.com'")
    ])
    error_message = "Every platform-object policy must admit each platform_automation_usernames entry."
  }

  assert {
    condition = (
      strcontains(kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces.manifest.spec.validations[0].expression, "request.namespace in []") &&
      strcontains(kubernetes_manifest.forbid_app_namespace_deletion.manifest.spec.validations[0].expression, "oldObject.metadata.name in []")
    )
    error_message = "With no destructive_teardown_namespaces, no app PVC or namespace may be deleted by platform automation."
  }
}

run "teardown_namespaces_are_explicit" {
  command = plan

  variables {
    destructive_teardown_namespaces = ["app-retired"]
  }

  assert {
    condition = (
      strcontains(kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces.manifest.spec.validations[0].expression, "request.namespace in [\"app-retired\"]") &&
      strcontains(kubernetes_manifest.forbid_app_namespace_deletion.manifest.spec.validations[0].expression, "oldObject.metadata.name in [\"app-retired\"]")
    )
    error_message = "destructive_teardown_namespaces must be rendered into the PVC and namespace delete policies."
  }
}

run "platform_automation_is_required" {
  command = plan

  variables {
    platform_automation_usernames = []
  }

  expect_failures = [var.platform_automation_usernames]
}
