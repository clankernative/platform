terraform {
  required_version = ">= 1.11.5"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.3"
    }
  }
}
provider "google" {
  project = var.project_id
  region  = var.region
}
