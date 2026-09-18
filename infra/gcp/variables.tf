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
