# Alerting: what happens when something is found, or when the pipeline
# that would find it breaks.
#
# Three things report here -- a scheduled query that looks for failed
# logins, an alarm for the normalization Lambda erroring, and an alarm
# for the log store growing unexpectedly fast.
#
# The last two matter as much as the first. A detection pipeline that has
# silently stopped running looks exactly like a quiet one, so the
# pipeline's own health is monitored alongside what it detects.
#
# Everything routes to one SNS topic for now. The project's shared
# incident-response path doesn't exist yet, so this stands in; swapping
# it later means repointing alarm_actions and one environment variable.
# Recorded in docs/DECISIONS.md (2026-09-19).

resource "aws_sns_topic" "detection_interim" {
  name = "fedramp-20x-ksi-detection-interim"

  # Alerts are derived from the audit log, so the evidence key. Every
  # publisher is granted in that key's policy (evidence_key.tf); each was
  # made to publish after the change (DECISIONS.md, 2026-10-01).
  kms_master_key_id = aws_kms_key.evidence.arn
}

# Email subscriptions require the recipient to click a confirmation link
# before anything is delivered. Until then the subscription sits pending.
resource "aws_sns_topic_subscription" "detection_interim_email" {
  topic_arn = aws_sns_topic.detection_interim.arn
  protocol  = "email"
  endpoint  = var.billing_alert_email
}

# Fires if the normalization Lambda throws at all -- threshold 0, not a
# rate. Any error means log events are being dropped on the floor.
resource "aws_cloudwatch_metric_alarm" "normalize_events_errors" {
  alarm_name          = "fedramp-20x-ksi-normalize-events-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0

  dimensions = {
    FunctionName = aws_lambda_function.normalize_events.function_name
  }

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}

# Catches runaway log delivery -- a misconfigured source writing far more
# than expected, which shows up as cost before it shows up as anything
# else. S3 has no capacity limit, so this is a spend guardrail, not a
# storage one. BucketSizeBytes is only published daily, hence the period.
resource "aws_cloudwatch_metric_alarm" "log_store_growth" {
  alarm_name          = "fedramp-20x-ksi-log-store-growth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400
  statistic           = "Average"
  threshold           = 5368709120 # 5 GB; generous for this project's volume

  dimensions = {
    BucketName  = aws_s3_bucket.log_store.bucket
    StorageType = "StandardStorage"
  }

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}

# --- The detection query itself ---
#
# A Lambda that runs one SQL query on a schedule and alerts if it returns
# anything. Query lives in lambda/run_detection_query/.

data "archive_file" "run_detection_query" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/run_detection_query/handler.py"
  output_path = "${path.module}/.build/run_detection_query.zip"
}

data "aws_iam_policy_document" "run_detection_query_permissions" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/fedramp-20x-ksi-run-detection-query*"
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults"]
    resources = [aws_athena_workgroup.log_corpus.arn]
  }

  statement {
    effect  = "Allow"
    actions = ["glue:GetTable", "glue:GetTables", "glue:GetDatabase", "glue:GetPartitions"]
    resources = [
      "arn:aws:glue:*:${data.aws_caller_identity.current.account_id}:catalog",
      "arn:aws:glue:*:${data.aws_caller_identity.current.account_id}:database/${aws_glue_catalog_database.log_corpus.name}",
      "arn:aws:glue:*:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.log_corpus.name}/*",
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.log_store.arn, "${aws_s3_bucket.log_store.arn}/normalized-raw/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.athena_results.arn, "${aws_s3_bucket.athena_results.arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.detection_interim.arn]
  }
}

resource "aws_iam_role" "run_detection_query" {
  name               = "fedramp-20x-ksi-run-detection-query"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Same as the normalizer's log group: created by Lambda, undeclared,
# unencrypted and never expiring until 2026-10-01.
import {
  to = aws_cloudwatch_log_group.run_detection_query
  id = "/aws/lambda/fedramp-20x-ksi-run-detection-query"
}

resource "aws_cloudwatch_log_group" "run_detection_query" {
  name              = "/aws/lambda/fedramp-20x-ksi-run-detection-query"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_iam_role_policy" "run_detection_query" {
  name   = "run-detection-query-permissions"
  role   = aws_iam_role.run_detection_query.id
  policy = data.aws_iam_policy_document.run_detection_query_permissions.json
}

resource "aws_lambda_function" "run_detection_query" {
  function_name    = "fedramp-20x-ksi-run-detection-query"
  role             = aws_iam_role.run_detection_query.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  timeout          = 90
  filename         = data.archive_file.run_detection_query.output_path
  source_code_hash = data.archive_file.run_detection_query.output_base64sha256

  # Passed as environment variables rather than hardcoded in the handler,
  # so redirecting alerts to the real incident-response path later is a
  # config change rather than a code change.
  environment {
    variables = {
      ATHENA_DATABASE  = aws_glue_catalog_database.log_corpus.name
      ATHENA_WORKGROUP = aws_athena_workgroup.log_corpus.name
      ALERT_TOPIC_ARN  = aws_sns_topic.detection_interim.arn
    }
  }
}

# Daily. The assessment framework's floor for this kind of check is every
# three days; running it daily is stricter and, at this query size, free.
resource "aws_cloudwatch_event_rule" "run_detection_query" {
  name                = "fedramp-20x-ksi-run-detection-query"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "run_detection_query" {
  rule      = aws_cloudwatch_event_rule.run_detection_query.name
  target_id = "run-detection-query"
  arn       = aws_lambda_function.run_detection_query.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke_detection" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.run_detection_query.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.run_detection_query.arn
}

# --- Who may publish to the interim topic ---
#
# Added when a review found the GuardDuty rule in posture.tf targeting this
# topic with nothing granting EventBridge permission to publish to it. That
# failure is silent: the rule matches, the delivery fails with
# FailedInvocations, and the detection path looks configured while
# producing nothing. The EventBridge-to-Lambda path next to it has its
# aws_lambda_permission, which is what made the asymmetry visible.
#
# Setting a topic policy REPLACES the default one, which allows the account
# owner. So the owner statement is restated here rather than inherited --
# without it the normalization Lambda's publish and ordinary console
# management both break.
data "aws_iam_policy_document" "detection_interim" {
  statement {
    sid    = "AllowAccountOwner"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "SNS:Publish",
      "SNS:Subscribe",
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:ListSubscriptionsByTopic",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
      "SNS:RemovePermission",
    ]

    resources = [aws_sns_topic.detection_interim.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # EventBridge, for the GuardDuty findings rule.
  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.detection_interim.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # CloudWatch, for the health and posture alarms.
  statement {
    sid    = "AllowCloudWatchAlarmPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.detection_interim.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "detection_interim" {
  arn    = aws_sns_topic.detection_interim.arn
  policy = data.aws_iam_policy_document.detection_interim.json
}
