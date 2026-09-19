# Spend guardrail. Emails if actual charges cross $50 in a calendar month.
#
# The number is a tripwire, not a budget: this environment is meant to be
# destroyed between sessions and cost only a few dollars a month. Crossing
# $50 almost certainly means something was left running.
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
