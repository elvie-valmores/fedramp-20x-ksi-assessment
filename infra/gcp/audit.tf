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

# --- Where Data Access logs are kept ---
#
# Until 2026-10-01 they went to _Default: global, under Google's key, and
# out of KSI-SVC-SIN row 1's reach. Neither built-in bucket can take a
# customer key -- CMEK is regional-only and set at creation -- so the logs
# are routed instead: into a regional bucket created with the GCP evidence
# key, and excluded from _Default. These are the customer-data access logs
# (who read the landing bucket, who queried the dataset, who decrypted),
# the audit-log class the evidence key exists for. Admin Activity stays in
# _Required, which cannot be rerouted. See DECISIONS.md, 2026-10-01.

data "google_logging_project_cmek_settings" "current" {
  project = var.gcp_project_id
}

# Logging encrypts the bucket as its own agent, so the agent needs the key
# before the bucket can be created with it.
resource "google_kms_crypto_key_iam_member" "logging_evidence" {
  crypto_key_id = google_kms_crypto_key.evidence.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_logging_project_cmek_settings.current.service_account_id}"
}

resource "google_logging_project_bucket_config" "data_access" {
  project   = var.gcp_project_id
  location  = var.gcp_region
  bucket_id = "fedramp-20x-ksi-data-access"

  # The same 30 days _Default kept them for: this change moves where they
  # are kept and under which key, not how long.
  retention_days = 30

  # Only settable at creation. Changing the key later means a new bucket.
  cmek_settings {
    kms_key_name = google_kms_crypto_key.evidence.id
  }

  depends_on = [google_kms_crypto_key_iam_member.logging_evidence]
}

resource "google_logging_project_sink" "data_access" {
  name        = "fedramp-20x-ksi-data-access"
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.data_access.id}"
  filter      = "LOG_ID(\"cloudaudit.googleapis.com/data_access\")"
}

# Keeps them out of _Default. Exclusions made through this API apply to the
# _Default sink. Created after the routing sink, so no Data Access log has
# nowhere to go while the two change over.
resource "google_logging_project_exclusion" "data_access_from_default" {
  name        = "fedramp-20x-ksi-data-access-to-own-bucket"
  description = "Data Access audit logs are routed to fedramp-20x-ksi-data-access, under the evidence key."
  filter      = "LOG_ID(\"cloudaudit.googleapis.com/data_access\")"

  depends_on = [google_logging_project_sink.data_access]
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
