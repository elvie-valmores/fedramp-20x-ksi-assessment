# The evidence collector's identity in CI.
#
# Step B of the collector schedule (DECISIONS.md, 2026-10-01). Persistent
# (see boundary.py): the collector runs while the application environment
# is down, so the identity that runs it cannot go down with it -- the same
# reason as the drift role.
#
# Assumed from GitHub Actions on main, through the existing OIDC provider
# and the same immutable-subject trust as the drift role.
#
# Its reads are the drift role's read policy, attached as a second copy of
# the same document rather than restated: several collector checks run the
# same `terraform plan` the drift job does, and one list cannot drift from
# itself. What only the collector does is in the second policy below. Both
# are enumerated; no managed policy (CNA-DFP, 2026-09-05).

resource "aws_iam_role" "github_collector" {
  name               = "fedramp-20x-ksi-github-collector"
  assume_role_policy = data.aws_iam_policy_document.github_drift_assume.json

  max_session_duration = 3600

  tags = {
    Component = "pipeline"
  }
}

resource "aws_iam_role_policy" "github_collector_plan_reads" {
  name   = "plan-reads"
  role   = aws_iam_role.github_collector.id
  policy = data.aws_iam_policy_document.github_drift.json
}

data "aws_iam_policy_document" "github_collector" {
  # Row 6's resolution simulates kms:Decrypt for every role and user.
  # Simulation reads policies and evaluates them; it changes nothing.
  statement {
    sid       = "ResolveDecryptPrincipals"
    effect    = "Allow"
    actions   = ["iam:SimulatePrincipalPolicy"]
    resources = ["*"]
  }

  # Row 1 lists every secret to check its key. Names and key IDs only: the
  # drift policy's deny on GetSecretValue applies to this role too.
  statement {
    sid       = "ListSecretsForEncryptionCheck"
    effect    = "Allow"
    actions   = ["secretsmanager:ListSecrets"]
    resources = ["*"]
  }

  # The inventory generator reads Config through its query API, which
  # config:Describe*/Get*/List* do not cover.
  statement {
    sid       = "QueryConfigInventory"
    effect    = "Allow"
    actions   = ["config:SelectResourceConfig"]
    resources = ["*"]
  }

  # mla-osm-ops-normalized-events-queryable runs a query, in the evidence
  # workgroup only. The workgroup enforces its own result location, scan
  # limit and encryption, so the role cannot run an unbounded or
  # unencrypted query through it.
  statement {
    sid    = "QueryEvidenceCorpus"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
    ]
    resources = [aws_athena_workgroup.log_corpus.arn]
  }

  # Athena writes results with the caller's credentials.
  statement {
    sid       = "WriteQueryResults"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.athena_results.arn}/results/*"]
  }
}

resource "aws_iam_role_policy" "github_collector" {
  name   = "collector"
  role   = aws_iam_role.github_collector.id
  policy = data.aws_iam_policy_document.github_collector.json
}

output "github_collector_role_arn" {
  description = "Assumed by the collect workflow. Set as the AWS_COLLECTOR_ROLE repository variable."
  value       = aws_iam_role.github_collector.arn
}
