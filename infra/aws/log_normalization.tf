# The log normalization pipeline: raw CloudTrail in, queryable events out.
#
# The flow is:
#   CloudTrail writes a log file to the log store
#     -> S3 fires an ObjectCreated notification
#     -> the Lambda rewrites each event into a common schema
#     -> output lands under normalized-raw/, partitioned by source and date
#     -> the Glue table at the bottom makes that path queryable from Athena
#
# The Lambda's own source is in lambda/normalize_events/. Terraform zips
# it at plan time rather than expecting a prebuilt artifact, so editing
# the Python and running apply is the whole deploy step.
#
# Currently AWS-only, and output is JSON rather than the more compact
# Parquet. Both are scope cuts, recorded in docs/DECISIONS.md
# (2026-09-19), not oversights.

data "archive_file" "normalize_events" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/normalize_events/handler.py"
  output_path = "${path.module}/.build/normalize_events.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "normalize_events" {
  name               = "fedramp-20x-ksi-normalize-events"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "normalize_events_permissions" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/fedramp-20x-ksi-normalize-events*"
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.log_store.arn}/AWSLogs/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_store.arn}/normalized-raw/*"]
  }
}

# The function's log group. Lambda created it on first run, unencrypted and
# kept forever, and nothing declared it, so neither drift nor the inventory
# checks could see it (the scoped Config recorder does not record log
# groups). Imported on 2026-10-01 rather than recreated, so its history
# stays.
import {
  to = aws_cloudwatch_log_group.normalize_events
  id = "/aws/lambda/fedramp-20x-ksi-normalize-events"
}

resource "aws_cloudwatch_log_group" "normalize_events" {
  name              = "/aws/lambda/fedramp-20x-ksi-normalize-events"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_iam_role_policy" "normalize_events" {
  name   = "normalize-events-permissions"
  role   = aws_iam_role.normalize_events.id
  policy = data.aws_iam_policy_document.normalize_events_permissions.json
}

resource "aws_lambda_function" "normalize_events" {
  function_name = "fedramp-20x-ksi-normalize-events"
  role          = aws_iam_role.normalize_events.arn
  handler       = "handler.handler" # file name . function name
  runtime       = "python3.13"
  timeout       = 60

  filename = data.archive_file.normalize_events.output_path
  # Redeploys the function whenever the source changes. Without this,
  # Terraform compares only the filename and never notices an edit.
  source_code_hash = data.archive_file.normalize_events.output_base64sha256
}

# S3 can only invoke the function if the function's own policy allows it.
# This is separate from the Lambda's execution role: that governs what the
# function can do, this governs who can call it.
resource "aws_lambda_permission" "allow_s3_invoke_normalize" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.normalize_events.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.log_store.arn
}

resource "aws_s3_bucket_notification" "log_store" {
  bucket = aws_s3_bucket.log_store.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.normalize_events.arn
    events              = ["s3:ObjectCreated:*"]

    # Narrow the trigger to CloudTrail's own log files. Without the
    # prefix filter the Lambda's own output under normalized-raw/ would
    # re-trigger it, and it would process its own writes in a loop.
    filter_prefix = "AWSLogs/"
    filter_suffix = ".json.gz"
  }

  # The permission must exist first, or S3 rejects the notification as
  # undeliverable at create time.
  depends_on = [aws_lambda_permission.allow_s3_invoke_normalize]
}

# --- Table definition ---
#
# Tells Athena how to read the Lambda's output: where the files are, that
# each line is a JSON object, and what columns to expect.
#
# The projection.* settings are the interesting part. Normally a query
# engine has to be told which partitions exist, either by running a
# crawler or by registering each new date by hand. Partition projection
# replaces that with a rule -- "dates from 7 days ago to today, one per
# day, at this path template" -- and Athena computes the partitions at
# query time. No crawler to schedule, no crawler charges, and a new day's
# data is queryable the moment it lands.
#
# $${source} escapes to a literal ${source} in the emitted template;
# Athena substitutes it, not Terraform.

resource "aws_glue_catalog_table" "normalized_events" {
  name          = "normalized_events"
  database_name = aws_glue_catalog_database.log_corpus.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "json"
    "projection.enabled"          = "true"
    "projection.source.type"      = "enum"
    "projection.source.values"    = "aws"
    "projection.dt.type"          = "date"
    "projection.dt.range"         = "NOW-7DAYS,NOW"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.log_store.bucket}/normalized-raw/source=$${source}/dt=$${dt}/"
  }

  storage_descriptor {
    location = "s3://${aws_s3_bucket.log_store.bucket}/normalized-raw/"

    # Read the files as plain lines of text, then hand each line to the
    # JSON deserializer below. That combination is what "newline-delimited
    # JSON" looks like to Athena.
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "time"
      type = "bigint"
    }
    columns {
      name = "class_uid"
      type = "int"
    }
    columns {
      name = "class_name"
      type = "string"
    }
    columns {
      name = "category_uid"
      type = "int"
    }
    columns {
      name = "severity_id"
      type = "int"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "status_detail"
      type = "string"
    }
    columns {
      name = "cloud"
      type = "struct<provider:string,account_uid:string,region:string>"
    }
    columns {
      name = "actor"
      type = "struct<user:struct<name:string,uid:string,type:string>>"
    }
    columns {
      name = "api"
      type = "struct<operation:string,service:struct<name:string>>"
    }
    columns {
      name = "src_endpoint"
      type = "struct<ip:string>"
    }
    columns {
      name = "metadata"
      type = "struct<original_source:string,original_event_id:string>"
    }
  }

  # These are not stored inside the files -- their values come from the
  # directory names (source=aws/dt=2026-09-19/), and they're queryable as
  # ordinary columns.
  partition_keys {
    name = "source"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }
}
