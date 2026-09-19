# Provider-native detection and posture assessment.
#
# KSI-CNA-EIS's determination is "assessment by managed services with the
# collector meta-assessing them". The distinction matters: these services
# are not this project's evidence collectors, they are the thing being
# assessed as present and functioning. An indicator that claims automated
# assessment and then evidences it with its own collector has assessed
# itself.
#
# Three services, each supplying a different finding class that
# KSI-SVC-EIS names:
#
#   GuardDuty    -- threat detection from CloudTrail, DNS and VPC flow logs
#   Security Hub -- posture findings and CIS benchmark comparisons, which
#                   KSI-CNA-IBP uses as its benchmark basis
#   Inspector    -- image and dependency vulnerabilities, which is the
#                   reason Security Hub Essentials was chosen over basic
#                   ECR scanning

# GuardDuty foundational. The design matrix records this as the
# audit-and-detection tier alongside CloudTrail and Config; the malware
# and runtime monitoring add-ons are deliberately not enabled, since they
# bill per GB scanned and per instance and this environment has neither
# instances nor volume.
resource "aws_guardduty_detector" "main" {
  enable = true

  # 15 minutes rather than the 6-hour default. KSI-IAM-SUS's graduated
  # response depends on a finding arriving while the session that caused
  # it is still live.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      # S3 data events, which is how exfiltration from the extract bucket
      # would be seen. Included in the foundational tier.
      enable = true
    }

    kubernetes {
      audit_logs {
        enable = false # no EKS in this architecture
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = false # no EC2 instances, and it bills per GB scanned
        }
      }
    }
  }

  tags = {
    Name = "fedramp-20x-ksi"
  }
}

# Security Hub. Enabling the account is separate from enabling any
# standard, and an account with no standards enabled produces no findings
# at all -- so both are declared.
resource "aws_securityhub_account" "main" {
  # Defaults are explicit here for KSI-CNA-DFP's build row 3: a managed
  # service's configurable feature set declared rather than inherited.
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# The CIS benchmark, which is what KSI-CNA-IBP's determination compares
# against. The GCP side has no equivalent at the free tier and that
# asymmetry is declared in the design rather than papered over.
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/3.0.0"

  depends_on = [aws_securityhub_account.main]
}

# AWS's own Foundational Security Best Practices. Broader than CIS and the
# source of most of the posture findings KSI-SVC-EIS consumes.
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Inspector, scanning container images in ECR. This is the half of
# KSI-SVC-EIS's build row 1 that basic ECR scanning does not cover:
# basic scanning reads OS packages only, which would leave every Python
# dependency in app/*/requirements.txt unscanned -- and those are the
# dependencies KSI-SCR-MON exists to monitor.
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}

# Findings out of GuardDuty and into the same interim topic the health
# alarms use, for the same reason and with the same note: the real
# detection path is KSI-IAM-SUS's and does not exist yet.
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "fedramp-20x-ksi-guardduty-findings"
  description = "GuardDuty findings at severity 4 and above, routed to the interim detection topic."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      # 4.0 and above is medium and higher. Low-severity findings in a
      # synthetic environment are almost entirely the environment
      # noticing itself.
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "detection-interim"
  arn       = aws_sns_topic.detection_interim.arn
}
