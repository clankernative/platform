terraform {
  required_version = ">= 1.8.0"
  backend "gcs" {}
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }
}
