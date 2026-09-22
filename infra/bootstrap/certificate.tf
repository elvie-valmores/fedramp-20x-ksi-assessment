# The public certificate for the application's load balancer.
#
# This lives in bootstrap rather than in the aws root, and the reason is the
# 2026-09-19 decision that DNS validation records are created by hand rather
# than through the DNS provider's Terraform integration.
#
# A hand-validated certificate must survive teardown. If it were declared in
# the aws root it would be destroyed with everything else, and every rebuild
# would need a human to create validation records in Cloudflare and wait for
# issuance before the environment could come up at all. That turns a
# five-minute apply into a manual gate, every session.
#
# So it belongs with the things the cost posture already keeps: applied once,
# rarely touched, and outliving the environment that consumes it. The aws root
# reads it with a data source and cannot destroy it.
#
# ACM certificates cost nothing to hold, so persisting it has no standing cost.
#
# Note this covers the load balancer's public listener only. The task-side
# certificate stays self-signed and is generated in the aws root -- see the
# 2026-09-19 decision recording why a trusted chain there would be validated
# by nothing in the path.

variable "app_domain" {
  description = <<-EOT
    Fully qualified domain for the application, e.g. ksi.example.com. Leave
    empty to skip certificate issuance entirely, which is the state the
    project is in until the domain is chosen. Supply via TF_VAR_app_domain.
  EOT
  type        = string
  default     = ""
}

resource "aws_acm_certificate" "app" {
  count = var.app_domain == "" ? 0 : 1

  domain_name       = var.app_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "fedramp-20x-ksi-app"
  }
}

# Deliberately no aws_acm_certificate_validation resource.
#
# That resource blocks the apply until the certificate is issued, which would
# mean this root hangs while someone opens Cloudflare in another window. With
# validation done by hand the honest flow is: apply, read the records below,
# create them, and let ACM issue asynchronously.
output "certificate_validation_records" {
  description = <<-EOT
    The DNS records to create by hand at the DNS provider, as CNAMEs.

    Create these and LEAVE THEM IN PLACE. ACM re-validates through the same
    records when it auto-renews, so deleting them after issuance breaks
    renewal at the next renewal, silently. Measured on the certificate
    actually issued for caliper.elvievalmores.com on 2026-09-22: 197 days
    of validity, expiring 2027-04-07, so renewal begins around 2027-02-06.
    Not the ~13 months this once said -- public certificate lifetimes have
    been shortening, so read the dates off the certificate rather than
    assuming a duration.
  EOT

  value = var.app_domain == "" ? [] : [
    for option in aws_acm_certificate.app[0].domain_validation_options : {
      name  = option.resource_record_name
      type  = option.resource_record_type
      value = option.resource_record_value
    }
  ]
}

output "certificate_arn" {
  description = "Issued certificate ARN. The aws root looks this up by domain rather than consuming this output, so the two roots stay decoupled."
  value       = var.app_domain == "" ? "" : aws_acm_certificate.app[0].arn
}
