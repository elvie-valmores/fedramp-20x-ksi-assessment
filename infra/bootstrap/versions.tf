terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Deliberately no backend block. This config creates the bucket that every
  # other root uses as a remote backend, so it cannot use that backend itself.
  # State for this root stays local, in infra/bootstrap/terraform.tfstate.
}
