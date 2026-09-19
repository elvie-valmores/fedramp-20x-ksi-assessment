# Spend guardrail, matching the AWS one in infra/aws/billing.tf: alert if
# this project's charges cross $50 in a month.
#
# GCP splits this across two resources -- the budget defines the
# threshold, and a notification channel defines where the alert goes.
resource "google_billing_budget" "monthly_guardrail" {
  billing_account = var.billing_account_id
  display_name    = "fedramp-20x-ksi-monthly-guardrail"

  budget_filter {
    projects = ["projects/${data.google_project.current.number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "50"
    }
  }

  # Fraction, not percent: 1.0 means alert at 100% of the $50 above.
  threshold_rules {
    threshold_percent = 1.0
  }

  all_updates_rule {
    monitoring_notification_channels = [google_monitoring_notification_channel.billing_email.id]
  }
}

resource "google_monitoring_notification_channel" "billing_email" {
  project      = var.gcp_project_id
  display_name = "fedramp-20x-ksi billing alert"
  type         = "email"

  labels = {
    email_address = var.billing_alert_email
  }
}
