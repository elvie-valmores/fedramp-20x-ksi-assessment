variable "aws_region" {
  description = "AWS region for project resources."
  type        = string
  default     = "us-east-1"
}

variable "billing_alert_email" {
  description = "Email that receives the monthly billing guardrail alert. Supply via TF_VAR_billing_alert_email or a gitignored terraform.tfvars — never commit it."
  type        = string
}

variable "app_domain" {
  description = <<-EOT
    Fully qualified domain the application is served on, e.g. ksi.example.com.

    Empty means the load balancer falls back to the imported self-signed
    certificate, which is where the project sits until the domain is chosen.
    When set, the certificate issued in infra/bootstrap is used instead and
    the disclosure file below is published.

    Supply via TF_VAR_app_domain.
  EOT
  type        = string
  default     = ""
}

variable "security_contact" {
  description = "Contact for the vulnerability disclosure program (KSI-PIY-RVD). Defaults to security@<app_domain>."
  type        = string
  default     = ""
}

variable "security_policy_url" {
  description = "URL of the published disclosure policy. Omitted from security.txt when empty rather than pointing at a page that does not exist."
  type        = string
  default     = ""
}

variable "database_instance_class" {
  description = "The database's instance class. db.t4g.small as declared; override for one session only when RDS lacks capacity for it (2026-10-07)."
  type        = string
  default     = "db.t4g.small"
}
