provider "kubernetes" {
  config_path    = var.kubeconfig_path != "" ? pathexpand(var.kubeconfig_path) : null
  config_context = var.kube_context != "" ? var.kube_context : null
}
