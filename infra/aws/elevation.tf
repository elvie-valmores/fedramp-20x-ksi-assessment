# --- Just-in-time elevation (KSI-IAM-JIT), 2026-10-03 ---
#
# The operator's standing access is read-only. Changing anything takes an
# elevation: a written justification, an ElevatedAdmin assignment for a
# bounded window, and its removal when the window closes. Before this the
# operator held AdministratorAccess standing, through InterimOperatorAdmin
# (identity_center.tf), under a change exception that named this as its
# exit.
#
#   OperatorReadOnly  standing. ReadOnlyAccess, plus starting an elevation,
#                     running Athena queries over the evidence, and taking
#                     the Terraform state lock so a plan can run
#   ElevatedAdmin     never standing. AdministratorAccess in us-east-1, one
#                     hour per sign-in, assigned only by the workflow below
#
# The workflow fixes who is elevated, to what, and where. Its input carries
# only the justification and the window, so starting one cannot elevate
# anyone else or to anything else. Every phase is recorded in the log store
# under elevations/ and every grant is alerted, so an elevation nobody
# expected is seen. Removing an assignment stops new sign-ins; a session
# already open ends within its hour.
#
# The backstop runs every 15 minutes and removes any ElevatedAdmin
# assignment that no running elevation accounts for -- a workflow that
# failed before revoking, one that was stopped, or one made by hand -- and
# stops any elevation older than the longest window. Release early with
# `elevate.sh release`: it stops the workflow, and the backstop removes the
# assignment.
#
# This is the management account, so Identity Center provisions the
# permission set's IAM role with the caller's own credentials. The workflow
# and the backstop therefore hold IAM role and SAML provider permissions,
# confined to Identity Center's reserved path and its provider.

locals {
  elevation_name          = "fedramp-20x-ksi-elevation"
  elevation_state_machine = "arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stateMachine:${local.elevation_name}"
  sso_account_arn         = "arn:aws:sso:::account/${data.aws_caller_identity.current.account_id}"
  reserved_role_path      = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/*"
  sso_saml_provider       = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/AWSSSO_*_DO_NOT_DELETE"

  # What provisioning and removing a permission set's role takes in the
  # management account, per Identity Center's documentation.
  sso_provisioning_actions = [
    "iam:AttachRolePolicy",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:PutRolePolicy",
    "iam:UpdateRole",
    "iam:UpdateRoleDescription",
    "iam:UpdateAssumeRolePolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
  ]
  sso_provider_actions = [
    "iam:CreateSAMLProvider",
    "iam:GetSAMLProvider",
    "iam:UpdateSAMLProvider",
  ]
}

# --- The standing role ---

resource "aws_ssoadmin_permission_set" "operator_read_only" {
  name             = "OperatorReadOnly"
  description      = "Standing read-only access. Changes go through an elevation (elevation.tf)."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
}

resource "aws_ssoadmin_managed_policy_attachment" "operator_read_only" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.operator_read_only.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "operator_read_only" {
  statement {
    sid       = "StartAnElevation"
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = [local.elevation_state_machine]
  }

  # Release early: the backstop removes the assignment once nothing holds it.
  statement {
    sid       = "StopAnElevation"
    effect    = "Allow"
    actions   = ["states:StopExecution"]
    resources = ["arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:execution:${local.elevation_name}:*"]
  }

  # Investigation, and the log_query checks run by hand.
  statement {
    sid       = "QueryTheEvidence"
    effect    = "Allow"
    actions   = ["athena:StartQueryExecution", "athena:StopQueryExecution"]
    resources = [aws_athena_workgroup.log_corpus.arn, aws_athena_workgroup.primary.arn]
  }

  statement {
    sid       = "WriteQueryResults"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.athena_results.arn}/*"]
  }

  # The evidence stores are under the evidence key, and the key policy
  # admits the operator through S3 only (OperatorUsesThroughS3).
  statement {
    sid       = "ReadEvidenceThroughS3"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.evidence.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  # `terraform plan` takes the S3 lock file (use_lockfile) even when it
  # changes nothing. The state itself is read through ReadOnlyAccess.
  statement {
    sid       = "TakeTheStateLock"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::fedramp-20x-ksi-tfstate-${data.aws_caller_identity.current.account_id}/*.tflock"]
  }
}

resource "aws_ssoadmin_permission_set_inline_policy" "operator_read_only" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.operator_read_only.arn
  inline_policy      = data.aws_iam_policy_document.operator_read_only.json
}

resource "aws_ssoadmin_account_assignment" "alex_operator_read_only" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.operator_read_only.arn

  principal_id   = data.aws_identitystore_user.alex.user_id
  principal_type = "USER"

  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# --- The elevated role ---
#
# No assignment here. Only the workflow assigns it. The region deny follows
# AWS's published example: global services, whose calls resolve to
# us-east-1 or to no region, are exempt.

resource "aws_ssoadmin_permission_set" "elevated_admin" {
  name             = "ElevatedAdmin"
  description      = "Assigned only for a justified, time-bound elevation (elevation.tf)."
  instance_arn     = local.sso_instance_arn
  session_duration = "PT1H"
}

resource "aws_ssoadmin_managed_policy_attachment" "elevated_admin" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.elevated_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "elevated_admin" {
  statement {
    sid    = "DenyOutsideTheHomeRegion"
    effect = "Deny"
    not_actions = [
      "account:*", "acm:*", "aws-marketplace:*", "aws-portal:*", "billing:*", "budgets:*",
      "ce:*", "cloudfront:*", "config:*", "cur:*", "ec2:DescribeRegions", "freetier:*",
      "globalaccelerator:*", "health:*", "iam:*", "identitystore:*", "invoicing:*", "kms:*",
      "organizations:*", "payments:*", "pricing:*", "route53:*", "route53domains:*",
      "s3:GetAccountPublic*", "s3:ListAllMyBuckets", "s3:PutAccountPublic*", "shield:*",
      "sso:*", "sts:*", "support:*", "tax:*", "trustedadvisor:*", "waf:*", "wafv2:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [data.aws_region.current.name]
    }
  }
}

resource "aws_ssoadmin_permission_set_inline_policy" "elevated_admin" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.elevated_admin.arn
  inline_policy      = data.aws_iam_policy_document.elevated_admin.json
}

# --- The record, the confirmation and the backstop ---

data "archive_file" "elevation" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/elevation/handler.py"
  output_path = "${path.module}/.build/elevation.zip"
}

resource "aws_iam_role" "elevation" {
  name               = local.elevation_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "elevation" {
  statement {
    sid       = "WriteItsLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.elevation.arn}:*"]
  }

  statement {
    sid       = "RecordInTheLogStore"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_store.arn}/elevations/*"]
  }

  statement {
    sid       = "AlertTheOperator"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.detection_interim.arn]
  }

  statement {
    sid       = "UseTheEvidenceKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.evidence.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com", "sns.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  statement {
    sid    = "ReadAndRemoveElevatedAssignments"
    effect = "Allow"
    actions = [
      "sso:ListAccountAssignments",
      "sso:DeleteAccountAssignment",
      "sso:DescribeAccountAssignmentCreationStatus",
      "sso:DescribeAccountAssignmentDeletionStatus",
    ]
    resources = [local.sso_instance_arn, aws_ssoadmin_permission_set.elevated_admin.arn, local.sso_account_arn]
  }

  statement {
    sid       = "RemoveTheProvisionedRole"
    effect    = "Allow"
    actions   = local.sso_provisioning_actions
    resources = [local.reserved_role_path]
  }

  statement {
    sid       = "ReadTheProvider"
    effect    = "Allow"
    actions   = local.sso_provider_actions
    resources = [local.sso_saml_provider]
  }

  statement {
    sid       = "SeeTheElevations"
    effect    = "Allow"
    actions   = ["states:ListExecutions"]
    resources = [local.elevation_state_machine]
  }

  statement {
    sid       = "StopAnOverdueElevation"
    effect    = "Allow"
    actions   = ["states:StopExecution"]
    resources = ["arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:execution:${local.elevation_name}:*"]
  }
}

resource "aws_iam_role_policy" "elevation" {
  name   = "elevation-permissions"
  role   = aws_iam_role.elevation.id
  policy = data.aws_iam_policy_document.elevation.json
}

resource "aws_cloudwatch_log_group" "elevation" {
  name              = "/aws/lambda/${local.elevation_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.evidence.arn
}

resource "aws_lambda_function" "elevation" {
  function_name    = local.elevation_name
  role             = aws_iam_role.elevation.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  timeout          = 120
  filename         = data.archive_file.elevation.output_path
  source_code_hash = data.archive_file.elevation.output_base64sha256

  environment {
    variables = {
      LOG_BUCKET         = aws_s3_bucket.log_store.bucket
      ALERT_TOPIC_ARN    = aws_sns_topic.detection_interim.arn
      INSTANCE_ARN       = local.sso_instance_arn
      PERMISSION_SET_ARN = aws_ssoadmin_permission_set.elevated_admin.arn
      ACCOUNT_ID         = data.aws_caller_identity.current.account_id
      # Built from the name: the workflow invokes this function, so its
      # ARN as an attribute would be a cycle.
      STATE_MACHINE_ARN = local.elevation_state_machine
    }
  }

  depends_on = [aws_cloudwatch_log_group.elevation, aws_iam_role_policy.elevation]
}

resource "aws_cloudwatch_event_rule" "elevation_sweep" {
  name                = "${local.elevation_name}-sweep"
  description         = "The elevation backstop (elevation.tf)"
  schedule_expression = "rate(15 minutes)"
}

resource "aws_cloudwatch_event_target" "elevation_sweep" {
  rule      = aws_cloudwatch_event_rule.elevation_sweep.name
  target_id = "elevation-sweep"
  arn       = aws_lambda_function.elevation.arn
  input     = jsonencode({ action = "sweep" })
}

resource "aws_lambda_permission" "elevation_sweep" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.elevation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.elevation_sweep.arn
}

# --- The workflow ---

data "aws_iam_policy_document" "states_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "elevation_workflow" {
  name               = "${local.elevation_name}-workflow"
  assume_role_policy = data.aws_iam_policy_document.states_assume.json
}

data "aws_iam_policy_document" "elevation_workflow" {
  statement {
    sid       = "RunTheSteps"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.elevation.arn]
  }

  statement {
    sid       = "AssignAndRemove"
    effect    = "Allow"
    actions   = ["sso:CreateAccountAssignment", "sso:DeleteAccountAssignment"]
    resources = [local.sso_instance_arn, aws_ssoadmin_permission_set.elevated_admin.arn, local.sso_account_arn]
  }

  statement {
    sid       = "ProvisionTheRole"
    effect    = "Allow"
    actions   = local.sso_provisioning_actions
    resources = [local.reserved_role_path]
  }

  statement {
    sid       = "UseTheProvider"
    effect    = "Allow"
    actions   = local.sso_provider_actions
    resources = [local.sso_saml_provider]
  }

  # Step Functions log delivery is configured through these account-level
  # calls, which take no resource.
  statement {
    sid    = "DeliverItsLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "elevation_workflow" {
  name   = "elevation-workflow-permissions"
  role   = aws_iam_role.elevation_workflow.id
  policy = data.aws_iam_policy_document.elevation_workflow.json
}

# Execution data included: the justification is in these logs as well as
# in the log store and the execution history.
resource "aws_cloudwatch_log_group" "elevation_workflow" {
  name              = "/aws/vendedlogs/states/${local.elevation_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.evidence.arn
}

locals {
  elevation_assignment = {
    InstanceArn      = local.sso_instance_arn
    PermissionSetArn = aws_ssoadmin_permission_set.elevated_admin.arn
    PrincipalId      = data.aws_identitystore_user.alex.user_id
    PrincipalType    = "USER"
    TargetId         = data.aws_caller_identity.current.account_id
    TargetType       = "AWS_ACCOUNT"
  }

  lambda_retry = [{
    ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 2
    MaxAttempts     = 3
    BackoffRate     = 2
  }]
}

resource "aws_sfn_state_machine" "elevation" {
  name     = local.elevation_name
  role_arn = aws_iam_role.elevation_workflow.arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.elevation_workflow.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  definition = jsonencode({
    Comment = "Just-in-time elevation to ElevatedAdmin (infra/aws/elevation.tf)"
    StartAt = "Record the request"
    States = {
      # Refuses a short justification or a window outside 15 to 240
      # minutes. A refusal fails here, before anything is granted.
      "Record the request" = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.elevation.arn
          Payload = {
            action        = "request"
            "execution.$" = "$$.Execution.Id"
            "input.$"     = "$"
          }
        }
        ResultSelector = {
          "seconds.$"       = "$.Payload.seconds"
          "minutes.$"       = "$.Payload.minutes"
          "justification.$" = "$.Payload.justification"
        }
        ResultPath = "$.request"
        Retry      = local.lambda_retry
        Next       = "Grant"
      }
      "Grant" = {
        Type           = "Task"
        Resource       = "arn:aws:states:::aws-sdk:ssoadmin:createAccountAssignment"
        Parameters     = local.elevation_assignment
        ResultSelector = { "request_id.$" = "$.AccountAssignmentCreationStatus.RequestId" }
        ResultPath     = "$.grant"
        Catch          = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Revoke" }]
        Next           = "Confirm the grant"
      }
      "Confirm the grant" = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.elevation.arn
          Payload = {
            action            = "granted"
            "execution.$"     = "$$.Execution.Id"
            "request_id.$"    = "$.grant.request_id"
            "justification.$" = "$.request.justification"
            "minutes.$"       = "$.request.minutes"
          }
        }
        ResultPath = null
        Retry      = local.lambda_retry
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "Revoke" }]
        Next       = "Hold"
      }
      "Hold" = {
        Type        = "Wait"
        SecondsPath = "$.request.seconds"
        Next        = "Revoke"
      }
      "Revoke" = {
        Type           = "Task"
        Resource       = "arn:aws:states:::aws-sdk:ssoadmin:deleteAccountAssignment"
        Parameters     = local.elevation_assignment
        ResultSelector = { "request_id.$" = "$.AccountAssignmentDeletionStatus.RequestId" }
        ResultPath     = "$.revoke"
        Retry          = [{ ErrorEquals = ["States.ALL"], IntervalSeconds = 10, MaxAttempts = 4, BackoffRate = 2 }]
        Next           = "Confirm the revocation"
      }
      "Confirm the revocation" = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.elevation.arn
          Payload      = { action = "revoked", "execution.$" = "$$.Execution.Id", "request_id.$" = "$.revoke.request_id" }
        }
        ResultPath = null
        Retry      = local.lambda_retry
        Next       = "Did the grant fail"
      }
      # A grant that failed and was cleaned up still ends the execution
      # failed, so the history shows it.
      "Did the grant fail" = {
        Type    = "Choice"
        Choices = [{ Variable = "$.error", IsPresent = true, Next = "Grant failed" }]
        Default = "Done"
      }
      "Grant failed" = { Type = "Fail", Error = "GrantFailed", Cause = "the grant failed; the assignment was removed" }
      "Done"         = { Type = "Succeed" }
    }
  })

  depends_on = [aws_iam_role_policy.elevation_workflow]
}
