# The deliberate test for KSI-MLA-EVC validate rows 1 to 3.
#
# One security group rule whose source range is a variable. Its default is
# private, so the source is compliant: a source scanner reads the default
# and passes it. Planned with -var allowed_cidr=0.0.0.0/0, the plan opens
# SSH to the internet, and only an evaluator reading the plan can see it.
# policy/deliberate_test.py plans it both ways and expects the gate to pass
# one and block the other, and the source scan to pass the file.
#
# Planned offline: no credentials, no backend, nothing applied, ever.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fixture"
  secret_key                  = "fixture"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

variable "allowed_cidr" {
  description = "Where administrative access may come from."
  type        = string
  default     = "10.0.0.0/16"
}

resource "aws_security_group" "admin" {
  name        = "fixture-admin"
  description = "Deliberate test fixture; never applied"
  vpc_id      = "vpc-00000000000000000"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.admin.id
  description       = "Administrative access"
  cidr_ipv4         = var.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
