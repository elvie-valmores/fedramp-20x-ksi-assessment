terraform {
  required_version = ">= 1.10.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # Same state backend AWS uses — one S3 bucket, different key. Terraform's
  # S3 backend just stores a JSON file; it has no opinion about which cloud
  # the resources it describes live in. No separate GCP state bucket needed.
  backend "s3" {}
}
