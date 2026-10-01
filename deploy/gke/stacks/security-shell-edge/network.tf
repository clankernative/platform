# Only the Google load balancer reaches the listener. App pods cannot bypass IAP.
resource "kubernetes_network_policy_v1" "deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.shell.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "listener" {
  metadata {
    name      = "shell-listener"
    namespace = var.namespace
  }
  spec {
    pod_selector { match_labels = local.selector }
    policy_types = ["Ingress"]
    ingress {
      dynamic "from" {
        for_each = ["35.191.0.0/16", "130.211.0.0/22"]
        content {
          ip_block { cidr = from.value }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "kubernetes_network_policy_v1" "https" {
  metadata {
    name      = "shell-provider-https"
    namespace = var.namespace
  }
  spec {
    pod_selector { match_labels = local.selector }
    policy_types = ["Egress"]
    egress {
      to {
        ip_block {
          cidr   = "0.0.0.0/0"
          except = distinct(concat(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"], var.cluster_cidrs))
        }
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "kubernetes_network_policy_v1" "dns" {
  metadata {
    name      = "shell-dns"
    namespace = var.namespace
  }
  spec {
    pod_selector { match_labels = local.selector }
    policy_types = ["Egress"]
    dynamic "egress" {
      for_each = ["169.254.20.10/32", "${var.kube_dns_service_ip}/32"]
      content {
        to {
          ip_block { cidr = egress.value }
        }
        ports {
          protocol = "UDP"
          port     = "53"
        }
        ports {
          protocol = "TCP"
          port     = "53"
        }
      }
    }
    egress {
      to {
        namespace_selector { match_labels = { "kubernetes.io/metadata.name" = "kube-system" } }
        pod_selector { match_labels = { "k8s-app" = "kube-dns" } }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}

resource "kubernetes_network_policy_v1" "workload_identity" {
  metadata {
    name      = "shell-workload-identity"
    namespace = var.namespace
  }
  spec {
    pod_selector { match_labels = local.selector }
    policy_types = ["Egress"]
    egress {
      to {
        ip_block { cidr = "169.254.169.252/32" }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
      ports {
        protocol = "TCP"
        port     = "987"
      }
    }
    # Dataplane V2 intercepts metadata at this address; retain both documented
    # ports so a GKE upgrade does not break token acquisition.
    egress {
      to {
        ip_block { cidr = "169.254.169.254/32" }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.shell]
}
