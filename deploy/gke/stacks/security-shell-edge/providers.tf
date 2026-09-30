provider "google" {
  project = var.project_id
}

# DNS-edit credentials come from the operator's process, never the instance repo.
provider "cloudflare" {}

provider "kubernetes" {
  config_path    = var.kubeconfig_path != "" ? pathexpand(var.kubeconfig_path) : null
  config_context = var.kube_context != "" ? var.kube_context : null
}
