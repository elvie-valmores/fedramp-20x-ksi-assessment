# GCP-side counterpart to infra/aws/billing.tf. Same guardrail idea: a
# monthly $50 threshold, alerting by email, checked before anything else
# gets built. See docs/PROJECT-CONTEXT.md's cost posture section.
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

data "google_project" "current" {
  project_id = var.gcp_project_id
}
