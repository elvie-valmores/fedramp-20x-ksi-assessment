# Customer-managed keys, one per data class.
#
# KSI-SVC-SIN's build row asks for four to five keys by data class, reused
# across related stores, rather than one key for everything or one key per
# resource. The reasoning is that a key is a blast radius: everything
# encrypted under one key is readable by anyone who can use that key, so
# the classes should follow who is permitted to decrypt rather than which
# service happens to hold the data.
#
# Four classes here:
#
#   database  -- customer data at rest, and its backups (database_key.tf,
#                persistent since 2026-10-02)
#   secrets   -- the task certificate and the database master password
#   logs      -- audit and container logs
#   artifacts -- container images and the worker's extracts
#
# KSI-SVC-ASM's build row 3 requires automatic annual rotation on every
# customer-managed key, which is set on all four.
#
# KSI-SVC-SIN's build row 6 is the one that takes work: decrypt granted
# only to principals in the declared role model, and key policy
# modification requiring elevation. The first is built here. The second
# belongs to KSI-IAM-JIT's elevation workflow, which does not exist yet --
# until it does, key administration sits with the Terraform principal and
# that is recorded rather than implied.

# The policy every key starts from: account root may administer. Key
# policies must leave some principal able to administer, because a KMS key
# whose policy locks out everyone is unrecoverable -- AWS support cannot
# undo it.
data "aws_iam_policy_document" "key_base" {
  statement {
    sid    = "AllowAccountAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

# --- secrets ---

data "aws_iam_policy_document" "key_secrets" {
  source_policy_documents = [data.aws_iam_policy_document.key_base.json]

  # The api decrypts its TLS certificate. The execution role decrypts
  # nothing here -- secrets reach the task through the application at
  # runtime rather than through task definition injection, so the
  # execution role never sees them.
  statement {
    sid    = "AllowDeclaredDecryptors"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.api_task.arn,
        aws_iam_role.migrate_task.arn,
      ]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    # The key is usable only through Secrets Manager, not directly. A
    # compromised task cannot use it to decrypt anything else that
    # happened to be encrypted under it.
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowSecretsManagerService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "secrets" {
  description             = "fedramp-20x-ksi: secret material"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key_secrets.json

  tags = {
    DataClass = "secrets"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/fedramp-20x-ksi-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# --- logs ---

data "aws_iam_policy_document" "key_logs" {
  source_policy_documents = [data.aws_iam_policy_document.key_base.json]

  # CloudWatch Logs encrypts log groups with this key. The condition binds
  # it to log groups in this account and region rather than to any caller
  # the service happens to act for.
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "fedramp-20x-ksi: audit and container logs"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key_logs.json

  tags = {
    DataClass = "logs"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/fedramp-20x-ksi-logs"
  target_key_id = aws_kms_key.logs.key_id
}
