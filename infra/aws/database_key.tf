# The database key, which outlives the environment so the backups can.
#
# Split out of kms.tf on 2026-10-02. The cost posture keeps database backups
# between sessions for recovery testing (KSI-RPL-TRC; DECISIONS.md,
# 2026-09-05), and the instance keeps its automated backups on deletion. But
# this key was ephemeral, scheduled for deletion at every teardown with a
# 7-day window, so every retained backup became permanently unrestorable a
# week after the session that made it. svc-sin-cfg-aws-backups-restorable
# found it. The backups' persistence was defeated by their key's lifecycle;
# now the key persists with them.
#
# The policy needs no change to cross the boundary: it names the account and
# the RDS service, no role, so nothing in it is destroyed with the
# environment (the reason artifacts_key.tf had to stop naming roles).
#
# Cost: about 1 USD a month for the key, which now exists between sessions.

data "aws_iam_policy_document" "key_database" {
  source_policy_documents = [data.aws_iam_policy_document.key_base.json]

  statement {
    sid    = "AllowRDSService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
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

resource "aws_kms_key" "database" {
  description             = "fedramp-20x-ksi: customer data at rest and its backups"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key_database.json

  tags = {
    DataClass = "database"
  }
}

resource "aws_kms_alias" "database" {
  name          = "alias/fedramp-20x-ksi-database"
  target_key_id = aws_kms_key.database.key_id
}
