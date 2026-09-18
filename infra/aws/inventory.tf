# KSI-PIY-GIV, build item 1: AWS Config recorder.
#
# Scoped to the resource types the determinations actually use, not "all
# supported types" — see docs/DECISIONS.md, 2026-09-05, "Config recorder
# scoped for cost, with the coverage consequence stated". AWS Config bills
# per configuration item and apply-and-destroy regenerates items every
# session, so narrower scope is a deliberate cost/coverage tradeoff, not an
# oversight. Extend resource_types as later build phases add resources.
locals {
  config_recorder_resource_types = [
    "AWS::S3::Bucket",
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::KMS::Key",
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::SecurityGroup",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::ECS::TaskDefinition",
    "AWS::RDS::DBInstance",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::WAFv2::WebACL",
    "AWS::SecretsManager::Secret",
    "AWS::CloudTrail::Trail",
    "AWS::ECR::Repository",
  ]
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "fedramp-20x-ksi-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config's delivery channel needs its own bucket, distinct from the
# Terraform state bucket bootstrap created — different lifecycle, different
# writer (the Config service, not us).
resource "aws_s3_bucket" "config_delivery" {
  bucket = "fedramp-20x-ksi-config-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "config_delivery_bucket" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_delivery.arn]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_delivery.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config_delivery.arn, "${aws_s3_bucket.config_delivery.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id
  policy = data.aws_iam_policy_document.config_delivery_bucket.json
}

resource "aws_config_configuration_recorder" "main" {
  name     = "fedramp-20x-ksi-recorder"
  role_arn = aws_iam_role.config.arn

  # include_global_resource_types is left unset: global types (IAM::User,
  # IAM::Role, IAM::Policy) are already named explicitly in resource_types
  # below, and combining that with the flag trips
  # InvalidRecordingGroupException.
  recording_group {
    all_supported  = false
    resource_types = local.config_recorder_resource_types
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "fedramp-20x-ksi-delivery"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}
