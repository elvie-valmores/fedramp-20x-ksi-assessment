provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "fedramp-20x-ksi-assessment"
      ManagedBy = "terraform"
    }
  }
}
