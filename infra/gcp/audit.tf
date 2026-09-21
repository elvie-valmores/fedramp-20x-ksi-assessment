# Audit logging and posture assessment on the GCP side.
#
# KSI-MLA-LET lists GCP Audit Logs as a source. KSI-SVC-EIS relies on
# Security Command Center findings for the GCP half of its provider posture
# evidence, and KSI-IAM-SUS relies on the same service as a detection
# source.

# --- Audit logs ---
#
# Admin Activity logs are always on and cannot be disabled. Data Access
# logs are off by default for most services, which is the gap this closes:
# without them, reading every object in the landing bucket and querying
# every row in the dataset leaves no trace, and KSI-MLA-LET's "logged,
# monitored and audited recorded as three distinct states per source"
# would record the first state falsely.
#
# Deliberately scoped to the services that hold customer data rather than
# applied project-wide with `allServices`. Data Access logging bills by
# volume, and a blanket grant would log the audit log reads themselves.
resource "google_project_iam_audit_config" "storage" {
  project = var.gcp_project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_project_iam_audit_config" "bigquery" {
  project = var.gcp_project_id
  service = "bigquery.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Key use, which is the one that matters most for KSI-SVC-SIN: the claim
# is not only that data is encrypted but that decryption is controlled, and
# a decrypt nobody logged is a control nobody can evidence.
resource "google_project_iam_audit_config" "kms" {
  project = var.gcp_project_id
  service = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
}

# --- Posture ---
#
# Security Command Center at the Standard tier, activated for this project
# rather than for an organization.
#
# The project sits outside any organization, as recorded in
# docs/DECISIONS.md on 2026-09-18 for KSI-PIY-GIV. Project-level activation
# is supported at the Standard tier, so the service is available -- but
# Google documents that certain detection modules and service integrations
# are unavailable at project scope because of the reduced access.
#
# That is a real and declared limitation on KSI-SVC-EIS's GCP-side finding
# source and on KSI-IAM-SUS's GCP detection path: the findings that arrive
# are genuine, and the set is narrower than an org-level activation would
# produce. It is the same shape as the gap KSI-CNA-IBP already declares for
# the GCP benchmark mapping, and it follows from the same root cause.
#
# Not declared in Terraform. The google provider has no resource for
# Standard-tier project activation -- the paid tiers have one, the free
# tier does not -- so this is an enablement of the API above plus a console
# action, and pretending otherwise with a null_resource shelling out would
# be declared state that does not describe anything.
#
# Recorded here rather than left to be discovered: KSI-SVC-ACM's build row
# 1 is "no console-created resources", and this is an exception to it. It
# belongs in the exception register with the others, carrying the reason
# that the platform exposes no declarative interface for this tier.
