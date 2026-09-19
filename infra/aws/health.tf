# Operational health.
#
# KSI-CNA-EIS reads operational state as three layers including running
# health, not only configured state: a service can be perfectly declared
# and not be running. The design matrix's environment table names target
# group health checks, ECS desired-count maintenance and CloudWatch alarms
# on service and job health as the evidence for that third layer.
#
# The first two are platform guarantees configured in edge.tf and
# compute.tf. This file is the third: the alarms that make a departure from
# intended running state visible rather than merely recoverable.
#
# Every alarm routes to the interim detection topic in detection.tf, for
# the reason recorded in docs/DECISIONS.md on 2026-09-19: the real
# detection path belongs to KSI-IAM-SUS and does not exist yet. Rewiring
# these when it does is a change of one attribute each.

# Running count below desired. This is the alarm that distinguishes "ECS
# replaced a task" from "ECS cannot place a task at all" -- the first is
# the platform working, the second is an outage the platform cannot fix.
resource "aws_cloudwatch_metric_alarm" "api_running_count" {
  count = local.deploy_count

  alarm_name        = "fedramp-20x-ksi-api-running-below-desired"
  alarm_description = "api has fewer running tasks than desired for 10 minutes. Placement is failing, not merely cycling."

  namespace   = "ECS/ContainerInsights"
  metric_name = "RunningTaskCount"
  statistic   = "Minimum"

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.api[0].name
  }

  comparison_operator = "LessThanThreshold"
  threshold           = 2
  period              = 300
  evaluation_periods  = 2

  # Container Insights is disabled on the cluster, so this metric may not
  # be published. Treating missing data as breaching would alarm
  # constantly; treating it as not breaching means the alarm is silent
  # rather than wrong. The target group alarm below is the one that works
  # regardless, and this one becomes live if Insights is ever enabled.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
  ok_actions    = [aws_sns_topic.detection_interim.arn]
}

# The alarm that does not depend on Container Insights. A healthy host
# count of zero means the load balancer has nothing to send traffic to,
# which is the user-visible failure regardless of what ECS thinks.
resource "aws_cloudwatch_metric_alarm" "api_unhealthy_targets" {
  count = local.deploy_count

  alarm_name        = "fedramp-20x-ksi-api-no-healthy-targets"
  alarm_description = "The load balancer has no healthy api targets. The service is down from outside."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HealthyHostCount"
  statistic   = "Minimum"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 60
  evaluation_periods  = 3

  # Breaching, not notBreaching. Missing data here means the load balancer
  # is reporting nothing about its targets, which is not a reason for
  # confidence.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
  ok_actions    = [aws_sns_topic.detection_interim.arn]
}

# Server-side errors the application returned, as distinct from errors the
# load balancer generated because there was nothing to talk to.
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  count = local.deploy_count

  alarm_name        = "fedramp-20x-ksi-api-5xx"
  alarm_description = "The api returned 5xx responses. The service is up and failing, which no availability alarm catches."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_Target_5XX_Count"
  statistic   = "Sum"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 10
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}

# The worker is a job rather than a service, so it has no target group and
# no request metrics.
#
# The obvious alarm -- RunningTaskCount from ECS/ContainerInsights -- is a
# trap here, and a review caught it: Container Insights is disabled on the
# cluster, so that metric is never published and the alarm would sit in
# INSUFFICIENT_DATA forever while appearing to watch something. The api has
# HealthyHostCount as a fallback that does not depend on Insights; the
# worker has no equivalent, so it needs a signal of its own.
#
# The signal used instead is the worker's own heartbeat. Every cycle logs
# exactly one of two lines -- it landed records, or it looked and the
# window was empty -- which is a direct measurement of the job doing its
# work rather than an inference from the platform that it exists. That is
# also the better evidence for KSI-CNA-EIS's third layer, running health,
# and it follows KSI-MLA-RVL's rule that a nil result counts only when the
# looking was recorded.
resource "aws_cloudwatch_log_metric_filter" "worker_cycle" {
  count = local.deploy_count

  name           = "fedramp-20x-ksi-worker-cycle"
  log_group_name = aws_cloudwatch_log_group.worker.name

  # Matches both terminal lines of cycle() in app/worker/main.py.
  pattern = "?landed ?\"extract window empty\""

  metric_transformation {
    name      = "WorkerCycles"
    namespace = "fedramp-20x-ksi"
    value     = "1"
    unit      = "Count"

    # Without this, a period with no cycles publishes no data point at all
    # rather than a zero, and the alarm cannot tell "stopped" from "not
    # reporting".
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "worker_not_cycling" {
  count = local.deploy_count

  alarm_name        = "fedramp-20x-ksi-worker-not-cycling"
  alarm_description = "The worker has completed no extract cycle in 45 minutes. Extracts to the analytics pipeline have stopped."

  namespace   = "fedramp-20x-ksi"
  metric_name = aws_cloudwatch_log_metric_filter.worker_cycle[0].metric_transformation[0].name
  statistic   = "Sum"

  comparison_operator = "LessThanThreshold"
  threshold           = 1

  # The worker cycles every 15 minutes, so three empty periods means it
  # has missed three consecutive cycles rather than been briefly slow.
  period             = 900
  evaluation_periods = 3

  # Breaching, not notBreaching. A worker publishing nothing is precisely
  # the condition this alarm exists to catch, so missing data is the
  # signal rather than the absence of one -- the mistake the replaced
  # alarm made.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
  ok_actions    = [aws_sns_topic.detection_interim.arn]
}

# --- Database ---

resource "aws_cloudwatch_metric_alarm" "database_storage" {
  alarm_name        = "fedramp-20x-ksi-database-storage-low"
  alarm_description = "Free storage below 2 GB. Storage autoscaling should have acted before this fires."

  namespace   = "AWS/RDS"
  metric_name = "FreeStorageSpace"
  statistic   = "Minimum"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  comparison_operator = "LessThanThreshold"
  threshold           = 2147483648 # 2 GiB
  period              = 300
  evaluation_periods  = 2
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}

# A burst balance heading to zero on a t-class instance means the database
# is about to become very slow for reasons that have nothing to do with
# the query being run, which is the failure mode most likely to be
# misdiagnosed.
resource "aws_cloudwatch_metric_alarm" "database_cpu_credits" {
  alarm_name        = "fedramp-20x-ksi-database-cpu-credits-low"
  alarm_description = "CPU credit balance is low. A t-class instance out of credits throttles to baseline."

  namespace   = "AWS/RDS"
  metric_name = "CPUCreditBalance"
  statistic   = "Minimum"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  comparison_operator = "LessThanThreshold"
  threshold           = 30
  period              = 300
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}

# --- Edge ---

# KSI-CNA-RVP's effectiveness evidence. A blocked request is the firewall
# doing its job, so this is not an outage alarm -- it is the signal that
# the environment is receiving attack traffic at all, which the
# determination records as otherwise unavailable in a synthetic
# environment with no real attackers.
resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  alarm_name        = "fedramp-20x-ksi-waf-blocking"
  alarm_description = "The web firewall is blocking requests. Not an outage -- the evidence KSI-CNA-RVP's effectiveness claim needs."

  namespace   = "AWS/WAFV2"
  metric_name = "BlockedRequests"
  statistic   = "Sum"

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 50
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.detection_interim.arn]
}
