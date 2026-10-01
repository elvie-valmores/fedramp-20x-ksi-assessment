variable "gcp_project_id" {
  description = "GCP project this root manages."
  type        = string
  default     = "fedramp-20x-ksi-assessment"
}

variable "gcp_region" {
  description = "Default GCP region for project resources."
  type        = string
  default     = "us-central1"
}

variable "billing_account_id" {
  description = "Billing account this project is linked to, for the budget alert."
  type        = string
}

variable "billing_alert_email" {
  description = "Email that receives the monthly billing guardrail alert. Supply via TF_VAR_billing_alert_email or a gitignored terraform.tfvars — never commit it."
  type        = string
}

# Who Terraform acts as. Locally, terraform-admin, impersonated (see
# provider.tf). In CI, nobody: the collector plans as the read-only
# federated principal and must never hold the token-creator grant on
# terraform-admin that impersonation needs (DECISIONS.md, 2026-10-01).
# Set TF_VAR_impersonate_service_account="" to plan as the ambient identity.
variable "impersonate_service_account" {
  description = "Service account the providers impersonate; empty for the ambient identity."
  type        = string
  default     = "terraform-admin@fedramp-20x-ksi-assessment.iam.gserviceaccount.com"
}
