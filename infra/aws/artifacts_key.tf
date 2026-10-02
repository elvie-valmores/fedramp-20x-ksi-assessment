# The artifacts key, which outlives the environment it encrypts for.
#
# Split out of kms.tf on 2026-09-22, when the container registry and the
# extract bucket moved to the persistent side of boundary.py. Both encrypt
# with this key, so a key that came and went with the application
# environment would have taken them with it.
#
# WHY THE POLICY NO LONGER NAMES ROLES
#
# It used to grant worker_task and task_execution directly. A KMS key policy
# validates that the principals it names exist -- PutKeyPolicy rejects an ARN
# that does not resolve -- and both of those roles are destroyed with the
# application environment. A persistent key carrying that policy simply
# cannot be created while the environment is down.
#
# So the key policy grants the account, and the roles are authorised by their
# own IAM policies instead. That is not a loosening in practice: compute.tf
# already grants worker_task `kms:GenerateDataKey` and `kms:DescribeKey` on
# this key with the same ViaService condition, and task_execution
# `kms:Decrypt` and `kms:DescribeKey`. The statements removed here were
# duplicating those grants, and what is lost is the key policy acting as a
# second backstop behind IAM rather than any capability.
#
# Recorded as a deliberate trade in DECISIONS.md, because a reader comparing
# this key to the other three will notice it is scoped differently and should
# find out why here rather than guess.
#
# The ECR service grant stays. A service principal is not an IAM role and has
# no existence to validate, so it carries no dependency on the environment --
# and ECR needs key access in the key policy to encrypt image layers at all.
#
# The secrets and logs keys stay in kms.tf and stay ephemeral: they encrypt
# things that are themselves destroyed. The database key was here too until
# 2026-10-02, on the same reasoning, which missed that the database's backups
# are kept between sessions; it is in database_key.tf now.

data "aws_iam_policy_document" "key_artifacts" {
  source_policy_documents = [data.aws_iam_policy_document.key_base.json]

  statement {
    sid    = "AllowECRService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecr.amazonaws.com"]
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

resource "aws_kms_key" "artifacts" {
  description             = "fedramp-20x-ksi: container images and data extracts"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key_artifacts.json

  tags = {
    DataClass = "artifacts"
  }
}

resource "aws_kms_alias" "artifacts" {
  name          = "alias/fedramp-20x-ksi-artifacts"
  target_key_id = aws_kms_key.artifacts.key_id
}
