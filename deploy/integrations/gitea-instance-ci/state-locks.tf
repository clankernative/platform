variable "plan_state_lock_objects" {
  description = "Optional exact object names in state_bucket_name that PR plans may create/delete for OpenTofu locking. Only .tflock objects are accepted; no state-content write authority is granted."
  type        = set(string)
  default     = []

  validation {
    condition = length(var.plan_state_lock_objects) <= 64 && alltrue([
      for name in var.plan_state_lock_objects : length(name) <= 512 && can(regex("^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*/[A-Za-z0-9_-]+\\.tflock$", name))
    ])
    error_message = "plan_state_lock_objects must contain at most 64 exact path-qualified .tflock names, with no wildcard, traversal, bucket URL or state-content object."
  }
}

resource "google_project_iam_custom_role" "plan_state_locks" {
  count       = length(var.plan_state_lock_objects) == 0 ? 0 : 1
  project     = var.project_id
  role_id     = "${replace(var.name, "-", "_")}_plan_state_locks"
  title       = "Instance CI named plan state locks"
  description = "Create/delete only reviewed OpenTofu lock objects; bucket binding supplies the exact object condition."
  permissions = ["storage.objects.create", "storage.objects.delete"]
}

resource "google_storage_bucket_iam_member" "plan_state_locks" {
  count  = length(var.plan_state_lock_objects) == 0 ? 0 : 1
  bucket = var.state_bucket_name
  role   = google_project_iam_custom_role.plan_state_locks[0].name
  member = "serviceAccount:${google_service_account.plan.email}"

  condition {
    title       = "only-reviewed-plan-state-locks"
    description = "No state-content writes or other object mutations."
    expression  = "resource.name in ${jsonencode([for name in sort(tolist(var.plan_state_lock_objects)) : "projects/_/buckets/${var.state_bucket_name}/objects/${name}"])}"
  }
}
