# The pipeline identity that outlives a teardown.
#
# Split out of pipeline.tf on 2026-09-22, after a drift run failed with "The
# web identity token provided could not be validated" -- which is what AWS
# says when no OIDC provider is registered in the account at all. The
# teardown had destroyed the provider and both roles along with the rest of
# pipeline.tf.
#
# The scoped drift check exists precisely to run while the application
# environment is down. Its own identity therefore cannot live in the half
# that goes down with it. Scoping the plan was necessary and not sufficient:
# a correct plan run by a principal that does not exist is still no signal.
#
# What lives here is free. An OIDC provider and IAM roles cost nothing to
# keep, so there is no cost argument for tearing them down, only the
# accident of which file they were written in.
#
# The build role deliberately stays in pipeline.tf. It grants push to
# repositories and use of a key that are themselves ephemeral, so it has
# nothing to do while they are gone, and keeping it here would mean holding
# references to resources that do not exist.
#
# boundary.py lists this file on the persistent side.

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  # The audience. Paired with the subject condition below, this is what
  # makes the trust specific rather than "any GitHub workflow anywhere".
  client_id_list = ["sts.amazonaws.com"]

  tags = {
    Name = "fedramp-20x-ksi-github"
  }
}

# --- The drift-detection role ---
#
# KSI-SVC-ACM build row 3: a scheduled plan in check mode across both
# clouds, with exit status treated as the drift signal.
#
# Read-only, and separate from the build role rather than folded into it. A
# plan needs to read most of the account, which is a much wider grant than
# publishing an image, and combining them would give the build path
# account-wide read for no reason.
#
# Note this role can plan but not apply. Apply remains with a human
# identity under the dated exception recorded in docs/DECISIONS.md on
# 2026-09-19, which closes when KSI-IAM-JIT's elevation workflow lands.
# Until then KSI-CMT-RMV build row 3 is satisfied by exception rather than
# by enforcement, and that is recorded rather than implied.

data "aws_iam_policy_document" "github_drift_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scheduled workflows run against the default branch, so the same
    # subject applies.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_subject]
    }
  }
}

resource "aws_iam_role" "github_drift" {
  name               = "fedramp-20x-ksi-github-drift"
  assume_role_policy = data.aws_iam_policy_document.github_drift_assume.json

  max_session_duration = 3600

  tags = {
    Component = "pipeline"
  }
}

data "aws_iam_policy_document" "github_drift" {
  # Read-only across the resource types this project declares. A plan must
  # refresh every resource in state, so this is necessarily broad in
  # breadth while staying narrow in depth: it can describe anything and
  # change nothing.
  statement {
    sid    = "RefreshDeclaredState"
    effect = "Allow"

    actions = [
      # The account analyzer (account.tf, 2026-10-03): its refresh, and the
      # collector's read of its findings (cna-mat-ops-aws-external-access-declared).
      "access-analyzer:GetAnalyzer",
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListFindings",
      "access-analyzer:ListTagsForResource",
      "acm:Describe*",
      "acm:List*",
      # Athena's workgroup read. Absent entirely until 2026-09-22, which is
      # one of the four gaps that made every drift run error rather than
      # report.
      "athena:Get*",
      "athena:List*",
      "budgets:Describe*",
      # ListTagsForResource, which Terraform calls on every budget refresh.
      # `Describe*` and `View*` do not cover it.
      "budgets:List*",
      "budgets:View*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "ec2:Describe*",
      # EBS default encryption (account.tf, 2026-10-03): Get, not Describe.
      "ec2:GetEbsDefaultKmsKeyId",
      "ec2:GetEbsEncryptionByDefault",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "ecs:Describe*",
      "ecs:List*",
      "elasticloadbalancing:Describe*",
      "events:Describe*",
      "events:List*",
      "glue:Get*",
      "guardduty:Get*",
      "guardduty:List*",
      "iam:Get*",
      "iam:List*",
      # Identity Center, from identity_center.tf. The permission set, its
      # policy attachment and the assignment read through sso; the user
      # lookup reads through identitystore. Added in the same change as the
      # resources, so the first drift run after them does not error.
      "identitystore:DescribeUser",
      "identitystore:GetUserId",
      "identitystore:ListUsers",
      # BatchGetAccountStatus is how the enabler resource reads its own
      # state, and it matches neither `Get*` nor `List*`.
      "inspector2:BatchGet*",
      "inspector2:Get*",
      "inspector2:List*",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "lambda:Get*",
      "lambda:List*",
      "logs:Describe*",
      "logs:List*",
      "rds:Describe*",
      "rds:List*",
      "s3:Get*",
      "s3:List*",
      # The control associations in securityhub_controls.tf read through
      # ListStandardsControlAssociations and BatchGetStandardsControlAssociations.
      "securityhub:BatchGet*",
      "securityhub:Describe*",
      "securityhub:Get*",
      "securityhub:List*",
      "sns:Get*",
      "sns:List*",
      # The SSM document sharing block in account.tf.
      "ssm:GetServiceSetting",
      "sso:Describe*",
      "sso:Get*",
      "sso:List*",
      # The elevation workflow (elevation.tf, 2026-10-03). Describe* also
      # returns an execution's input -- the justification -- which the
      # collector's JIT checks read.
      "states:Describe*",
      "states:List*",
      "sts:GetCallerIdentity",
      "wafv2:Get*",
      "wafv2:List*",
    ]

    resources = ["*"]
  }

  # The plan reads and writes the state lock, so state access is read-write
  # even though nothing else is. Scoped to the state bucket alone.
  statement {
    sid    = "AccessRemoteState"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}",
      "arn:aws:s3:::fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}/*",
    ]
  }

  # Refreshing a secret's state reads its metadata, never its value --
  # which is true of a secret and false of a secret *version*, whose refresh
  # calls GetSecretValue.
  #
  # This deny was briefly reverted on 2026-09-22 to let an unscoped drift
  # plan refresh `aws_secretsmanager_secret_version.task_tls`, at the cost of
  # letting this role read a private key. Scoping the plan to the
  # persistence boundary removed the reason: `secrets.tf` is on the
  # ephemeral side, so a scoped plan never refreshes a secret version and
  # never needs to read one. The grant is gone and the deny is whole again.
  #
  # Stated as an explicit deny rather than a mere absence so that a later
  # widening of the read grant above cannot quietly pick it up. If drift is
  # ever widened to cover the application environment, this is the statement
  # that will stop it, and that is the moment to re-take the decision rather
  # than delete the line.
  statement {
    sid       = "NeverReadSecretValues"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_drift" {
  name   = "drift"
  role   = aws_iam_role.github_drift.id
  policy = data.aws_iam_policy_document.github_drift.json
}

output "github_drift_role_arn" {
  description = "Assumed by the drift workflow. Set as the AWS_DRIFT_ROLE repository variable."
  value       = aws_iam_role.github_drift.arn
}

output "ecr_registry" {
  description = "Registry hostname the build workflow pushes to."
  value       = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
}
