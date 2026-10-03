# AWS Config -- records the configuration of resources in this account.
# This is the source the inventory generator queries; see
# inventory/aws_source.py.
#
# Standing it up takes three separate resources, because AWS models them
# separately: a recorder (what to watch), a delivery channel (where to
# write configuration history), and a status resource (the on switch). A
# recorder without the status resource exists but records nothing.
#
# The type list below is deliberately narrow rather than "everything AWS
# supports". Config bills per configuration item recorded, and this
# environment is destroyed and rebuilt often, which regenerates every
# item each time. Narrower scope costs less and covers less -- a tradeoff
# recorded in docs/DECISIONS.md (2026-09-05). Keep it in sync with
# RESOURCE_TYPES in inventory/aws_source.py.
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

# The recorder runs as Config's service-linked role (Security Hub Config.1,
# 2026-10-03). Until then it ran as fedramp-20x-ksi-config-recorder, a
# custom role carrying the AWS-managed AWS_ConfigRole policy: a managed
# policy on a workload identity, which the CNA-DFP decision of 2026-09-05
# bars, and a role whose permissions AWS changed without a commit here.
# The service-linked role is AWS's to define and is scoped by AWS to Config.
# Delivery is unaffected: the bucket policy and the evidence key already
# grant Config's service principal, not the role.
# The role did not exist in this account until this change, so it is
# declared here rather than assumed: AWS creates a service-linked role on
# first use only through some paths, and PutConfigurationRecorder is not
# one that waits for it.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

# Config writes its configuration history here. Kept separate from the
# Terraform state bucket: different writer (the Config service, not us)
# and different lifecycle.
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

# The evidence key (evidence_key.tf), since 2026-09-30.
resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    # One KMS call per bucket key rather than per object, which is what keeps
    # a CloudTrail-and-Config write rate cheap under a customer key.
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
  role_arn = aws_iam_service_linked_role.config.arn

  # include_global_resource_types is intentionally unset. The global
  # types (IAM::User, IAM::Role, IAM::Policy) are already named
  # explicitly below, and AWS rejects the combination of an explicit
  # type list plus that flag with InvalidRecordingGroupException.
  recording_group {
    all_supported  = false
    resource_types = local.config_recorder_resource_types
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "fedramp-20x-ksi-delivery"
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket

  # Config encrypts what it delivers with this key, as the recorder role,
  # which the key policy names (evidence_key.tf).
  s3_kms_key_arn = aws_kms_key.evidence.arn

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# Configuration history kept 90 days, as the log store (Security Hub S3.13
# and the lean retention set, 2026-10-03). The inventory generator queries
# Config's API, not these files, so expiring them changes nothing it reads.
resource "aws_s3_bucket_lifecycle_configuration" "config_delivery" {
  bucket = aws_s3_bucket.config_delivery.id

  rule {
    id     = "retain-ninety-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Config's own configuration item history, which it keeps seven years by
# default (2026-10-03, the lean retention set). 90 days, as the delivered
# files and the log store.
resource "aws_config_retention_configuration" "main" {
  retention_period_in_days = 90
}
