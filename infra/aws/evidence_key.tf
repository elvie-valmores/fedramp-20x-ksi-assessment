# The evidence key: one customer-managed key for the audit-log data class.
#
# KSI-SVC-SIN build row 1 asks for "four to five keys by data class, reused
# across related stores". This is the audit-log class: the CloudTrail log
# store (and the normalized events beside it), the Config delivery bucket,
# and the Athena results derived from both. Persistent (see boundary.py),
# because every one of those stores is.
#
# Until 2026-09-30 all three buckets were SSE-S3, where AWS holds the key and
# anyone with s3:GetObject reads the plaintext. With this key, reading also
# takes kms:Decrypt, which this policy grants by name -- that is build row 6,
# "decrypt granted only to principals in the declared role model".
#
# WHAT CAN GO WRONG, AND HOW IT WAS CHECKED
#
# A key that a writer cannot use does not make the writer fail loudly. It
# makes it stop writing. CloudTrail keeps recording and delivers nothing;
# Config reports a delivery error nobody reads. So this change was not done
# at apply. It was done when fresh CloudTrail files, normalized events,
# Config deliveries and Athena results were each seen landing under this key
# (DECISIONS.md, 2026-09-30).
#
# Objects written before the change stay SSE-S3. Object Lock stops them being
# rewritten, and they age out with the 7-day retention, so the store is
# entirely under this key a week after the change.
#
# WHAT IS NOT BUILT
#
# Build row 6 also says key policy modification requires JIT elevation. The
# elevation workflow does not exist, so the operator's standing admin (the
# 2026-09-19 exception) can change this policy, including to grant itself
# more. The alert below covers deletion and disabling; policy changes are
# visible in CloudTrail and not yet alerted on.

locals {
  # Built rather than read from aws_cloudtrail.main, which depends on this
  # key: the reference would be a cycle.
  trail_arn = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/fedramp-20x-ksi-trail"

  # The operator's Identity Center role. Matched by pattern because the
  # suffix is Identity Center's to choose and changes if the permission set
  # is reprovisioned. See identity_center.tf.
  operator_role_pattern = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_InterimOperatorAdmin_*"
}

resource "aws_kms_key" "evidence" {
  description = "fedramp-20x-ksi evidence: CloudTrail, Config and Athena results"

  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = data.aws_iam_policy_document.key_evidence.json

  # The objects this key encrypts are under Object Lock. A key scheduled for
  # deletion takes readable evidence with it, and the lock would still stop
  # anyone deleting the unreadable objects.
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name      = "fedramp-20x-ksi-evidence"
    DataClass = "audit-log"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/fedramp-20x-ksi-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

data "aws_iam_policy_document" "key_evidence" {
  # Administration through IAM, without use. The account can manage the key
  # -- Terraform needs that, and the drift role reads it -- but no statement
  # here lets an IAM policy alone decrypt with it.
  statement {
    sid    = "AccountAdministersKey"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "kms:CancelKeyDeletion",
      "kms:Create*",
      "kms:Delete*",
      "kms:Describe*",
      "kms:Disable*",
      "kms:Enable*",
      "kms:Get*",
      "kms:List*",
      "kms:Put*",
      "kms:Revoke*",
      "kms:RotateKeyOnDemand",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:Update*",
    ]
    resources = ["*"]
  }

  # Deleting or disabling this key makes locked evidence unreadable. Only
  # root -- the AWS break-glass identity, with MFA -- may do either. The
  # operator's admin does not reach past an explicit deny.
  statement {
    sid    = "OnlyBreakGlassDeletesOrDisables"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["kms:ScheduleKeyDeletion", "kms:DisableKey"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # CloudTrail encrypts each log file itself, with the trail's ARN as the
  # encryption context. Scoped to this trail.
  statement {
    sid    = "CloudTrailEncryptsLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  # Digest files, which make log file validation work, are written once an
  # hour. If CloudTrail writes them without its own encryption, the bucket
  # default applies this key through S3 with an S3 encryption context, which
  # the statement above does not match. Still scoped to this trail, and only
  # through S3. Which path digests take was checked after the change
  # (DECISIONS.md, 2026-09-30); this stays either way, because a gap in the
  # digest chain is an integrity gap in the evidence.
  statement {
    sid    = "CloudTrailWritesThroughBucketDefault"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  statement {
    sid    = "CloudTrailDescribesKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # The declared roles that read or write evidence, named directly so no IAM
  # policy is needed and none can widen it. Each is persistent: a key policy
  # naming a role that does not exist is rejected (see artifacts_key.tf).
  #
  #   normalize_events     reads CloudTrail files, writes normalized events
  #   run_detection_query  reads normalized events and writes results, via Athena
  #   github_collector     the same, for the collector's query check in CI
  #
  # The Config recorder role was here until the first apply showed Config
  # never delivers as it (the next statement).
  #
  # Only through S3, so a role holding this cannot call KMS directly on
  # ciphertext taken from anywhere else.
  statement {
    sid    = "DeclaredRolesUseThroughS3"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.normalize_events.arn,
        aws_iam_role.run_detection_query.arn,
        aws_iam_role.github_collector.arn,
      ]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  # Config delivers as the Config service itself, which is what the Config
  # bucket's policy grants, not as the recorder role. The first apply named
  # the role here instead: PutDeliveryChannel's writability check was
  # refused, after the bucket default had already moved to this key, which
  # left Config's next delivery refused too. AWS's documented statement for
  # Config delivery, scoped to this account (DECISIONS.md, 2026-09-30).
  statement {
    sid    = "ConfigDeliversSnapshots"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # The two Lambdas' log groups (log_normalization.tf, detection.tf). Logs
  # encrypts and decrypts with the log group's ARN as context, so this is
  # scoped to this project's Lambda log groups by name.
  statement {
    sid    = "LogsEncryptsLambdaLogGroups"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt*",
      "kms:Describe*",
      "kms:Encrypt*",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/fedramp-20x-ksi-*"]
    }
  }

  # The detection topic (detection.tf) is encrypted with this key since
  # 2026-10-01, and every publisher must be able to use it -- a publisher
  # that cannot is not refused loudly; its alerts simply do not arrive.
  # CloudWatch alarms and EventBridge rules publish as their services, as
  # AWS documents for encrypted topics. The topic's own policy already
  # limits publishing to this account.
  statement {
    sid    = "AlertServicesPublishToTopic"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
  }

  # The detection Lambda publishes as its role, only through SNS.
  statement {
    sid    = "DetectionLambdaPublishesThroughSns"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.run_detection_query.arn]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sns.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  # The operator reads evidence through S3 and Athena: the collector's
  # log_query checks and any investigation. Standing, under the same
  # exception as the operator's permission set, and closing with it.
  statement {
    sid    = "OperatorUsesThroughS3"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = [local.operator_role_pattern]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

# An attempt to delete or disable this key, successful or denied. Denied
# calls reach EventBridge too, so an attempt by the operator -- which the
# deny above stops -- still raises the alert.
resource "aws_cloudwatch_event_rule" "evidence_key_threat" {
  name        = "fedramp-20x-ksi-evidence-key-threat"
  description = "ScheduleKeyDeletion or DisableKey against the evidence key, routed to the interim detection topic."

  # Two shapes, because CloudTrail records the two outcomes differently. A
  # successful call names the key in `resources`. A denied one has
  # `resources` and `requestParameters` both null, and names the key only
  # in `errorMessage` ("... on resource: <key ARN> with an explicit deny").
  # The first version matched `resources` alone, so it could only ever
  # catch root -- the one principal allowed -- and never the attempts the
  # deny exists to stop. Found by attempting it (DECISIONS.md, 2026-10-01).
  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ScheduleKeyDeletion", "DisableKey"]
      "$or" = [
        { resources = { ARN = [aws_kms_key.evidence.arn] } },
        { errorMessage = [{ wildcard = "*${aws_kms_key.evidence.arn}*" }] },
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "evidence_key_threat" {
  rule      = aws_cloudwatch_event_rule.evidence_key_threat.name
  target_id = "detection-interim"
  arn       = aws_sns_topic.detection_interim.arn
}
