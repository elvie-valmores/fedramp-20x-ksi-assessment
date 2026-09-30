# Security Hub controls for services this project never deploys, disabled
# with a stated reason.
#
# Persistent (see boundary.py), with the standards they belong to.
#
# Measured on 2026-09-30 (DECISIONS.md): of about 370 checks a day, 187 were
# controls for services nothing here declares. They cannot find anything,
# and most ended in WARNING, but each is a billed check. That was about half
# of Security Hub's projected cost after its trial.
#
# The rule is by service, and it is one-way:
#
#   - A control is off only if its service appears nowhere in this
#     project's Terraform. Controls for services that are declared stay on
#     even while they fail, or warn because the application environment is
#     torn down. Those are findings, and turning them off would be
#     remediating the measurement.
#   - Account-wide guardrails stay on for services that are unused, because
#     they protect against the service being misused later: EMR.2 (EMR block
#     public access) and SSM.7 (SSM document public sharing). SSM.7 was
#     failing, and the setting is fixed in account.tf rather than excused
#     here.
#
# Adopting any service below means deleting its line here in the same
# change. The list was generated from the live FSBP control list, so
# controls AWS adds later arrive enabled, and a later review catches them.

locals {
  securityhub_out_of_architecture = {
    APIGateway = [
      "APIGateway.1", "APIGateway.2", "APIGateway.3", "APIGateway.4", "APIGateway.5", "APIGateway.8", "APIGateway.9", "APIGateway.10",
      "APIGateway.11",
    ]
    AppSync          = ["AppSync.2", "AppSync.5"]
    AutoScaling      = ["AutoScaling.1", "AutoScaling.2", "AutoScaling.3", "AutoScaling.6", "AutoScaling.9"]
    Autoscaling      = ["Autoscaling.5"]
    Backup           = ["Backup.1"]
    BedrockAgentCore = ["BedrockAgentCore.1", "BedrockAgentCore.2", "BedrockAgentCore.5", "BedrockAgentCore.6"]
    CloudFormation   = ["CloudFormation.3", "CloudFormation.4"]
    CloudFront = [
      "CloudFront.1", "CloudFront.3", "CloudFront.4", "CloudFront.5", "CloudFront.6", "CloudFront.7", "CloudFront.8", "CloudFront.9",
      "CloudFront.10", "CloudFront.12", "CloudFront.13", "CloudFront.15", "CloudFront.16", "CloudFront.17",
    ]
    CodeBuild    = ["CodeBuild.1", "CodeBuild.2", "CodeBuild.3", "CodeBuild.4", "CodeBuild.7"]
    Cognito      = ["Cognito.1", "Cognito.2", "Cognito.3", "Cognito.4", "Cognito.5", "Cognito.6"]
    Connect      = ["Connect.2"]
    DataFirehose = ["DataFirehose.1"]
    DataSync     = ["DataSync.1"]
    DMS = [
      "DMS.1", "DMS.6", "DMS.7", "DMS.8", "DMS.9", "DMS.10", "DMS.11", "DMS.12",
      "DMS.13",
    ]
    DocumentDB       = ["DocumentDB.1", "DocumentDB.2", "DocumentDB.3", "DocumentDB.4", "DocumentDB.5", "DocumentDB.6"]
    DynamoDB         = ["DynamoDB.1", "DynamoDB.2", "DynamoDB.3", "DynamoDB.6", "DynamoDB.7"]
    EFS              = ["EFS.1", "EFS.2", "EFS.3", "EFS.4", "EFS.7", "EFS.8"]
    EKS              = ["EKS.1", "EKS.2", "EKS.8", "EKS.9"]
    ElastiCache      = ["ElastiCache.1", "ElastiCache.2", "ElastiCache.3"]
    ElasticBeanstalk = ["ElasticBeanstalk.1", "ElasticBeanstalk.2", "ElasticBeanstalk.3"]
    EMR              = ["EMR.1", "EMR.3", "EMR.4"]
    ES               = ["ES.1", "ES.2", "ES.3", "ES.4", "ES.5", "ES.6", "ES.7", "ES.8"]
    FSx              = ["FSx.1", "FSx.2", "FSx.3", "FSx.4", "FSx.5"]
    Kinesis          = ["Kinesis.1", "Kinesis.3"]
    Macie            = ["Macie.1", "Macie.2"]
    MQ               = ["MQ.2"]
    MSK              = ["MSK.1", "MSK.3", "MSK.4", "MSK.5", "MSK.6"]
    Neptune          = ["Neptune.1", "Neptune.2", "Neptune.3", "Neptune.4", "Neptune.5", "Neptune.6", "Neptune.7", "Neptune.8"]
    NetworkFirewall  = ["NetworkFirewall.2", "NetworkFirewall.3", "NetworkFirewall.4", "NetworkFirewall.5", "NetworkFirewall.6", "NetworkFirewall.9", "NetworkFirewall.10"]
    Opensearch = [
      "Opensearch.1", "Opensearch.2", "Opensearch.3", "Opensearch.4", "Opensearch.5", "Opensearch.6", "Opensearch.7", "Opensearch.8",
      "Opensearch.10",
    ]
    PCA = ["PCA.1"]
    Redshift = [
      "Redshift.1", "Redshift.2", "Redshift.3", "Redshift.4", "Redshift.6", "Redshift.7", "Redshift.8", "Redshift.10",
      "Redshift.15", "Redshift.18",
    ]
    RedshiftServerless = ["RedshiftServerless.1", "RedshiftServerless.2", "RedshiftServerless.3", "RedshiftServerless.5", "RedshiftServerless.6"]
    Route53            = ["Route53.2"]
    SageMaker = [
      "SageMaker.1", "SageMaker.2", "SageMaker.3", "SageMaker.4", "SageMaker.5", "SageMaker.8", "SageMaker.9", "SageMaker.10",
      "SageMaker.11", "SageMaker.12", "SageMaker.13", "SageMaker.14", "SageMaker.15", "SageMaker.16", "SageMaker.17", "SageMaker.19",
    ]
    ServiceCatalog = ["ServiceCatalog.1"]
    SES            = ["SES.3"]
    SQS            = ["SQS.1", "SQS.3"]
    SSM            = ["SSM.1", "SSM.2", "SSM.3", "SSM.4", "SSM.6"]
    StepFunctions  = ["StepFunctions.1"]
    Transfer       = ["Transfer.2", "Transfer.3"]
    WorkSpaces     = ["WorkSpaces.1", "WorkSpaces.2"]
  }

  securityhub_disabled_reason = "Service not deployed in this project (securityhub_controls.tf); nothing for the control to evaluate. Re-enable on adoption."

  # Macie is a choice, not an absence. The design classifies data by
  # declaration (KSI-MLA-ALA's three tiers) rather than by scanning for it,
  # and Macie bills per bucket and per GB inspected.
  securityhub_reasons = {
    Macie = "Macie not adopted: data is classified by declaration (KSI-MLA-ALA tiers), not by discovery scanning. See DECISIONS.md, 2026-09-30."
  }

  securityhub_disabled = merge(
    {
      for pair in flatten([
        for service, ids in local.securityhub_out_of_architecture : [
          for id in ids : { id = id, service = service }
        ]
      ]) :
      "fsbp/${pair.id}" => {
        standards_arn = aws_securityhub_standards_subscription.fsbp.standards_arn
        control_id    = pair.id
        reason        = lookup(local.securityhub_reasons, pair.service, local.securityhub_disabled_reason)
      }
    },
    # CIS v3.0 names its controls differently but associates by the same
    # security control ID. EFS.1 is its only control for an undeployed
    # service.
    {
      "cis/EFS.1" = {
        standards_arn = aws_securityhub_standards_subscription.cis.standards_arn
        control_id    = "EFS.1"
        reason        = local.securityhub_disabled_reason
      }
    },
  )
}

resource "aws_securityhub_standards_control_association" "disabled" {
  for_each = local.securityhub_disabled

  standards_arn       = each.value.standards_arn
  security_control_id = each.value.control_id
  association_status  = "DISABLED"
  updated_reason      = each.value.reason
}
