# This state was first applied through a wrapper that called these resources as
# module.tenancy. They are now root resources of this stack.

moved {
  from = module.tenancy.kubernetes_storage_class_v1.app_sqlite_rwo
  to   = kubernetes_storage_class_v1.app_sqlite_rwo
}

moved {
  from = module.tenancy.kubernetes_storage_class_v1.app_sqlite_hyperdisk_rwo
  to   = kubernetes_storage_class_v1.app_sqlite_hyperdisk_rwo
}

moved {
  from = module.tenancy.kubernetes_manifest.pd_snapshot_class
  to   = kubernetes_manifest.pd_snapshot_class
}

moved {
  from = module.tenancy.kubernetes_manifest.require_runtime_service_account
  to   = kubernetes_manifest.require_runtime_service_account
}

moved {
  from = module.tenancy.kubernetes_manifest.require_runtime_service_account_binding
  to   = kubernetes_manifest.require_runtime_service_account_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_service_account_changes_in_app_namespaces
  to   = kubernetes_manifest.forbid_service_account_changes_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_service_account_changes_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_service_account_changes_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_rbac_changes_in_app_namespaces
  to   = kubernetes_manifest.forbid_rbac_changes_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_rbac_changes_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_rbac_changes_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.require_app_service_label
  to   = kubernetes_manifest.require_app_service_label
}

moved {
  from = module.tenancy.kubernetes_manifest.require_app_service_label_binding
  to   = kubernetes_manifest.require_app_service_label_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces
  to   = kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_pvc_deletion_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_app_namespace_deletion
  to   = kubernetes_manifest.forbid_app_namespace_deletion
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_app_namespace_deletion_binding
  to   = kubernetes_manifest.forbid_app_namespace_deletion_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_statefulset_volume_claim_templates_in_app_namespaces
  to   = kubernetes_manifest.forbid_statefulset_volume_claim_templates_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_statefulset_volume_claim_templates_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_statefulset_volume_claim_templates_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces
  to   = kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_platform_pvc_mutation_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces
  to   = kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces
}

moved {
  from = module.tenancy.kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces_binding
  to   = kubernetes_manifest.forbid_platform_resource_mutation_in_app_namespaces_binding
}

moved {
  from = module.tenancy.kubernetes_manifest.protect_platform_contract_configmap
  to   = kubernetes_manifest.protect_platform_contract_configmap
}

moved {
  from = module.tenancy.kubernetes_manifest.protect_platform_contract_configmap_binding
  to   = kubernetes_manifest.protect_platform_contract_configmap_binding
}
