# KSI-MLA-OSM, build item 2 (scoped): schema normalization, AWS side.
#
# Scope for this build: CloudTrail events only, mapped to two OCSF
# classes (Authentication, API Activity) -- "critical event classes
# first" per the documented adoption norm. GCP-side normalization and
# NDJSON-to-Parquet compaction are deferred; see docs/DECISIONS.md,
# 2026-09-19.

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

resource "aws_iam_role_policy" "normalize_events" {
  name   = "normalize-events-permissions"
  role   = aws_iam_role.normalize_events.id
  policy = data.aws_iam_policy_document.normalize_events_permissions.json
}

resource "aws_lambda_function" "normalize_events" {
  function_name    = "fedramp-20x-ksi-normalize-events"
  role             = aws_iam_role.normalize_events.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  timeout          = 60
  filename         = data.archive_file.normalize_events.output_path
  source_code_hash = data.archive_file.normalize_events.output_base64sha256
}

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
    filter_prefix       = "AWSLogs/"
    filter_suffix       = ".json.gz"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke_normalize]
}

# --- Queryable table over the normalized output ---
#
# JSON, not Parquet -- compaction to Parquet is deferred (see file
# header). Partition projection means no crawler and no manual
# add-partition calls; Athena computes valid partitions from the
# declared range at query time.

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
    location      = "s3://${aws_s3_bucket.log_store.bucket}/normalized-raw/"
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

  partition_keys {
    name = "source"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }
}
