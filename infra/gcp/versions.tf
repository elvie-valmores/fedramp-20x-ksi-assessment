terraform {
  required_version = ">= 1.10.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }

    # Only for google_project_service_identity, which creates a service
    # agent before first use of its service. The GA provider has no
    # equivalent. See analytics.tf.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
  }

  # State lives in the same S3 bucket the AWS roots use, under a different
  # key. The backend only stores a JSON file and has no opinion about
  # which cloud the resources it tracks live in, so a second state bucket
  # on GCP would be redundant.
  #
  # Bucket and key are supplied at init time via -backend-config; see
  # backend.hcl.example.
  backend "s3" {}
}
