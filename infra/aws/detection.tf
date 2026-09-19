# KSI-MLA-OSM, build items 5-6 (interim): one detection query and the
# delivery-failure/store-growth alarms. No detection path exists yet
# (that's KSI-IAM-SUS's build) -- alerts route to a standalone SNS topic
# as a stated interim sink until that's built. See docs/DECISIONS.md,
# 2026-09-19.

resource "aws_sns_topic" "detection_interim" {
  name = "fedramp-20x-ksi-detection-interim"
}

resource "aws_sns_topic_subscription" "detection_interim_email" {
  topic_arn = aws_sns_topic.detection_interim.arn
  protocol  = "email"
  endpoint  = var.billing_alert_email
}

# Delivery failure (AU-5): alarm on the normalization Lambda's own error count.
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

# Store growth (AU-4): alarm if the log store grows sharply -- a rough
# guardrail against runaway or misconfigured delivery, not a capacity
# limit, since the store has none.
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

# --- One detection query: failed console logins ---

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

  environment {
    variables = {
      ATHENA_DATABASE  = aws_glue_catalog_database.log_corpus.name
      ATHENA_WORKGROUP = aws_athena_workgroup.log_corpus.name
      ALERT_TOPIC_ARN  = aws_sns_topic.detection_interim.arn
    }
  }
}

# Cadence: the catalog's machine-based minimum is 3 days
# (VDR-TFR-MVX); daily is stricter and costs effectively nothing extra
# at this query size.
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
