# The public edge: load balancer, TLS, and the web firewall.
#
# This is the single deliberate entry point in the architecture. Everything
# else is private, and KSI-CNA-RNT's build row 2 requires a versioned list
# of resources permitted inbound from the internet -- that list has one
# entry, and this file is it.
#
# KSI-CNA-RVP is the determination built here: protecting against attack
# traffic and other unwanted activity. Shield Standard is free, automatic
# and applies to the load balancer without being declared anywhere, which
# is also its weakness -- it exposes almost nothing about its own
# effectiveness. WAF is what supplies reviewable metrics, and the design
# matrix records Shield Advanced as rejected at roughly 3,000 USD a month.

resource "aws_security_group" "alb" {
  name        = "fedramp-20x-ksi-alb"
  description = "The one public entry point. HTTPS and HTTP from the internet."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-alb"
  }
}

# The only two rules in this environment that name 0.0.0.0/0 as a source.
# KSI-CNA-RNT's verification is "no inbound 0.0.0.0/0 outside the declared
# public-facing list", so these are expected to appear and expected to be
# the only ones.
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet -- the declared public entry point"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
}

# HTTP exists only to redirect. Closing it entirely would mean a plain
# request times out rather than being told to use TLS, which trains users
# to retry rather than to upgrade.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from the internet, redirected to HTTPS"

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 80
  to_port     = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_api" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS to the api service"

  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = local.api_port
  to_port                      = local.api_port
}

resource "aws_lb" "main" {
  name               = "fedramp-20x-ksi"
  load_balancer_type = "application"
  internal           = false

  subnets         = aws_subnet.public[*].id
  security_groups = [aws_security_group.alb.id]

  # KSI-CNA-ULN's build row 5, session bounds. A connection held open
  # indefinitely outlives the conditions that authorised it; 60 seconds is
  # the AWS default stated explicitly rather than inherited, per
  # KSI-CNA-DFP.
  idle_timeout = 60

  # Headers that arrived claiming to be from somewhere else are dropped
  # rather than forwarded. Without this the application sees attacker-
  # controlled X-Forwarded-For values as though the load balancer set them.
  drop_invalid_header_fields = true

  enable_deletion_protection = false # this environment is meant to be destroyed

  # HTTP desync mitigation at the strictest setting: requests that are
  # ambiguous under the HTTP specification are rejected rather than
  # normalised and passed on.
  desync_mitigation_mode = "strictest"

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb"
    enabled = true
  }

  tags = {
    Name = "fedramp-20x-ksi"
  }

  # The load balancer validates that it can write access logs at creation
  # time, so the bucket policy granting that has to exist first. Terraform
  # infers a dependency on the bucket but not on its policy, so without
  # this the create fails intermittently depending on ordering. The
  # CloudTrail resource in log_corpus.tf carries the same depends_on for
  # the same reason.
  depends_on = [aws_s3_bucket_policy.alb_logs]
}

# --- Access logs ---
#
# A separate bucket from the log store, for one reason: the load balancer
# writes these with a service principal that does not support KMS
# customer-managed keys, and the log store requires them. Rather than
# weaken the log store's encryption to accommodate one writer, the access
# logs land here and are pulled into the corpus by the normalization path.
resource "aws_s3_bucket" "alb_logs" {
  bucket = "fedramp-20x-ksi-alb-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3 rather than SSE-KMS. The ELB log delivery principal cannot
      # write to a bucket encrypted with a customer-managed key; this is a
      # platform constraint, recorded in docs/DECISIONS.md rather than
      # left as an unexplained inconsistency with the other buckets.
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}

# The ELB service account differs per region and is the principal that
# writes access logs in the older regions; newer ones use
# logdelivery.elasticloadbalancing.amazonaws.com. Both are granted, since
# which applies depends on the region and getting it wrong fails the
# load balancer's creation rather than merely the logging.
data "aws_elb_service_account" "main" {}

data "aws_iam_policy_document" "alb_logs_bucket" {
  statement {
    sid    = "AllowELBAccountWrite"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.main.arn]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
  }

  statement {
    sid    = "AllowLogDeliveryWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs_bucket.json
}

# --- Target group and listeners ---

resource "aws_lb_target_group" "api" {
  name        = "fedramp-20x-ksi-api"
  port        = local.api_port
  target_type = "ip" # awsvpc networking: tasks have their own ENIs

  # HTTPS, not HTTP. KSI-SVC-SIN's build row 2 requires TLS continue to
  # the task rather than terminate at the load balancer, so this leg is
  # encrypted too. The load balancer does not verify the task's
  # certificate -- it cannot be configured to -- which is why the
  # determination's claim is confidentiality on this hop rather than
  # authenticity.
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id

  # Liveness, not readiness. /healthz deliberately does not touch the
  # database: a health check that fails during a database blip causes ECS
  # to replace tasks that are themselves fine.
  health_check {
    enabled             = true
    path                = "/healthz"
    protocol            = "HTTPS"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # Drain time before a deregistered task is killed. Long enough for
  # in-flight requests to finish, short enough that a deploy is not slow.
  deregistration_delay = 30

  tags = {
    Service = "api"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"

  # TLS 1.3 and 1.2 only. The named policies that include 1.0 and 1.1 are
  # still available and still the default in places, which is why this is
  # stated.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = aws_acm_certificate.public.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# --- Web firewall ---

resource "aws_wafv2_web_acl" "main" {
  name  = "fedramp-20x-ksi"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS's baseline rule set: the common web exploits, at the managed
  # group's own default actions.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # The application talks to Postgres, so SQL injection rules are directly
  # relevant rather than generically included.
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLi"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting: the "other unwanted activity" half KSI-CNA-RVP names,
  # which the managed groups do not cover. 2,000 requests per five minutes
  # from one address is far above anything legitimate at this environment's
  # volume and far below what would hurt.
  rule {
    name     = "RateLimitPerAddress"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "fedramp20xksi"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "fedramp-20x-ksi"
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# KSI-CNA-RVP's evidence is metrics and blocked-request records, which
# means the firewall has to log. The log group name prefix is required by
# WAF and is not a convention choice.
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-fedramp-20x-ksi"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  # Request bodies can carry customer data, and a firewall log is a
  # different retention and a different reader from the database. Redacted
  # rather than logged and then protected.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}
