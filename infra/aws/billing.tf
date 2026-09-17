# One guardrail: if actual spend crosses $50 in a calendar month, email the
# address below. $50 is the number PROJECT-CONTEXT.md already names as the
# signal that something from a prior session was not torn down.
resource "aws_budgets_budget" "monthly_guardrail" {
  name         = "fedramp-20x-ksi-monthly-guardrail"
  budget_type  = "COST"
  limit_amount = "50"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.billing_alert_email]
  }
}
