terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    # Generates the self-signed certificate the api task serves. ACM
    # cannot issue one without a domain to validate, and AWS Private CA
    # costs more than the rest of the environment combined -- see
    # secrets.tf.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    # Holds the disclosure file's expiry as a value that changes on a
    # declared rotation rather than on every plan. See edge.tf.
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  # Bucket, key, region and locking are supplied at `terraform init` time via
  # -backend-config=backend.hcl (see backend.hcl.example). Not hardcoded here:
  # the bucket name is account-specific and comes from infra/bootstrap's
  # output, not something to fix into version-controlled config.
  backend "s3" {}
}
