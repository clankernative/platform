output "storage_class_name" {
  description = "StorageClass for platform-managed app PVCs. The app-edge stack's PVC storage class must equal this."
  value       = kubernetes_storage_class_v1.app_sqlite_rwo.metadata[0].name
}

output "volume_snapshot_class_name" {
  description = "Retain-policy VolumeSnapshotClass for app PVC snapshots."
  value       = kubernetes_manifest.pd_snapshot_class.manifest.metadata.name
}
