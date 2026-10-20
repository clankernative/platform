provider "google" {
  project = var.project_id
  zone    = var.storage.zone
}

provider "kubernetes" {
  config_path    = var.kubeconfig_path == null ? null : pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}
