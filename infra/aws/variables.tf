variable "aws_region" {
  description = "AWS region for project resources."
  type        = string
  default     = "us-east-1"
}

variable "billing_alert_email" {
  description = "Email that receives the monthly billing guardrail alert. Supply via TF_VAR_billing_alert_email or a gitignored terraform.tfvars — never commit it."
  type        = string
}
