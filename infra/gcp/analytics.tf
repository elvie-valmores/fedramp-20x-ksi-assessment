# The analytics store, and the things that hold data on the GCP side.
#
# This is the reason the persona spans two clouds at all. The design matrix
# is honest that a real two-person team would more likely pick one; the
# second cloud is here because cross-cloud normalization is harder and
# demonstrates more, not because the persona would organically build it.
#
# Four determinations are built here:
#
#   KSI-SVC-SIN  -- customer-managed keys across every store, dataset IAM
#                   bound to declared roles with no primitive roles, public
#                   access prevention and uniform bucket-level access
#   KSI-CNA-RNT  -- the second resource category: resources with no network
#                   interface, bounded by resource policy rather than by
#                   firewall rule
#   KSI-RPL-RRO  -- the analytics store recorded as reconstructible rather
#                   than restorable, and the landing zone as regenerable
#   KSI-SVC-VRI  -- the registry that holds the pipeline image, with
#                   immutable tags

# --- APIs ---
#
# Declared rather than clicked. KSI-SVC-ACM's build row 1 is "all
# machine-based resources declared in code, no console-created resources",
# and an API enabled by hand is exactly the kind of state that exists
# without appearing anywhere in declared state.
resource "google_project_service" "analytics" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudscheduler.googleapis.com",
    # Vulnerability scanning of Artifact Registry images on push, and their
    # continuous re-analysis for 30 days after (KSI-SVC-EIS verify row 1,
    # 2026-10-02). Until then the analytics image's OS packages were scanned
    # nowhere; its Python dependencies are audited in CI. Container Analysis
    # holds the results and is a dependency of Container Scanning, declared
    # so drift sees both. About 0.26 USD per image pushed.
    "containeranalysis.googleapis.com",
    "containerscanning.googleapis.com",
    "run.googleapis.com",
    "securitycenter.googleapis.com",
    "sts.googleapis.com",
  ])

  project = var.gcp_project_id
  service = each.value

  # Leave the API enabled if this resource is destroyed. Disabling an API
  # on teardown breaks anything else in the project still using it, and
  # re-enabling has a propagation delay that makes the next apply flaky.
  disable_on_destroy = false
}

# --- Keys ---
#
# KSI-SVC-SIN build row 1 asks for four to five keys by data class across
# both clouds. The AWS side has four; these are the GCP counterparts for
# the classes that exist here. The same reasoning applies: a key is a blast
# radius, so the classes follow who may decrypt.

resource "google_kms_key_ring" "main" {
  name     = "fedramp-20x-ksi"
  location = var.gcp_region

  depends_on = [google_project_service.analytics]
}

resource "google_kms_crypto_key" "analytics" {
  name     = "analytics"
  key_ring = google_kms_key_ring.main.id

  # KSI-SVC-ASM build row 3: automatic annual rotation on every
  # customer-managed key. Expressed in seconds because that is the only
  # unit the API takes.
  rotation_period = "31536000s" # 365 days

  # The environment is destroyed between sessions and keys are among the
  # things the cost posture deliberately preserves. 30 days is the GCP
  # minimum destroy window and applies if the key is ever removed.
  #
  # Deliberately no prevent_destroy lifecycle block. It reads as prudent
  # and is not: it would make `terraform destroy` fail for the entire
  # root, blocking teardown of everything else, to guard an operation that
  # is already reversible -- GCP schedules key destruction rather than
  # performing it, and the window above is that guard.
  destroy_scheduled_duration = "2592000s" # 30 days

  labels = {
    data_class = "analytics"
  }
}

resource "google_kms_crypto_key" "artifacts" {
  name                       = "artifacts"
  key_ring                   = google_kms_key_ring.main.id
  rotation_period            = "31536000s"
  destroy_scheduled_duration = "2592000s"

  labels = {
    data_class = "artifacts"
  }
}

# The audit-log class, the GCP counterpart of AWS's evidence key, added on
# 2026-10-01. It encrypts the asset-feed topic. The two log buckets that
# hold GCP's audit logs, _Default and _Required, cannot take it: both are
# in the global region, which CMEK does not support, and CMEK can only be
# set when a bucket is created. That is a platform limit, recorded as an
# exception (DECISIONS.md, 2026-10-01). Permanent, like every key here:
# Cloud KMS keys cannot be deleted, only their versions destroyed.
resource "google_kms_crypto_key" "evidence" {
  name                       = "evidence"
  key_ring                   = google_kms_key_ring.main.id
  rotation_period            = "31536000s"
  destroy_scheduled_duration = "2592000s"

  labels = {
    data_class = "audit-log"
  }
}

# Each service encrypts with its own agent identity, so each needs its own
# grant on the key it uses. Scoped per key rather than per key ring: a
# grant on the ring would let the storage agent decrypt image layers.
#
# The identities are read, not constructed. Their addresses are derivable
# from the project number and writing them out that way is what this file
# did until 2026-09-22 -- which produced three correct-looking strings and
# a failed apply, because a service agent does not exist until its service
# is first used and `Service account ... does not exist` is a 400, not a
# retryable condition. Reading each one creates it as a side effect, and
# ties the grant to the identity rather than to a guess about its name.
data "google_storage_project_service_account" "gcs" {}

# BigQuery's agent is the one exception, since 2026-10-01. Reading it calls
# projects.getServiceAccount, which requires bigquery.jobs.create -- the
# right to run BigQuery jobs -- and the collector, which plans this root
# read-only from CI, would have needed that just to learn an address. The
# reason above no longer applies to it: the agent was created by the read on
# 2026-09-22 and exists. Its address was checked against state before the
# switch (identical), and the plan showed no change to the grant that uses
# it (DECISIONS.md, 2026-10-01). If this project were ever rebuilt from
# nothing, the agent would need inducing first, as the comment above says.
locals {
  bigquery_agent_email = "bq-${data.google_project.current.number}@bigquery-encryption.iam.gserviceaccount.com"
}

# Artifact Registry has no data source that induces its agent, and the GA
# provider has no google_project_service_identity. This is the one place
# the beta provider is used, and it is used rather than running
# `gcloud beta services identity create` by hand because a declarative
# interface exists here -- unlike Security Command Center's free tier,
# which is a recorded exception for exactly the opposite reason.
resource "google_project_service_identity" "artifactregistry" {
  provider = google-beta
  service  = "artifactregistry.googleapis.com"

  depends_on = [google_project_service.analytics]
}

resource "google_kms_crypto_key_iam_member" "storage_analytics" {
  crypto_key_id = google_kms_crypto_key.analytics.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_kms_crypto_key_iam_member" "bigquery_analytics" {
  crypto_key_id = google_kms_crypto_key.analytics.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${local.bigquery_agent_email}"
}

# Pub/Sub's agent, read the same way as Artifact Registry's.
resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  service  = "pubsub.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "pubsub_evidence" {
  crypto_key_id = google_kms_crypto_key.evidence.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

resource "google_kms_crypto_key_iam_member" "artifactregistry_artifacts" {
  crypto_key_id = google_kms_crypto_key.artifacts.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.artifactregistry.email}"
}

# --- The landing zone ---
#
# Intermediate between the extract that leaves AWS and the load into
# BigQuery. KSI-RPL-RRO records it as regenerable: nothing here is the only
# copy of anything, because the source rows are still in the AWS database
# and the pipeline can be re-run.

resource "google_storage_bucket" "landing" {
  name     = "${var.gcp_project_id}-landing"
  location = var.gcp_region

  # KSI-SVC-SIN build row 4. Uniform access means object ACLs cannot
  # re-introduce per-object permissions that bucket policy does not know
  # about -- the GCS equivalent of the exposure S3 public access blocks
  # close.
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.analytics.id
  }

  versioning {
    enabled = true
  }

  # KSI-SVC-PRR build row 3: lifecycle windows, so intermediate data is
  # residue with an expiry rather than residue that accumulates.
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      age                = 7
      with_state         = "ARCHIVED"
      num_newer_versions = 1
    }
    action {
      type = "Delete"
    }
  }

  # Access logs would go here in a production deployment. Audit Logs cover
  # the admin-activity half already; data-access logging for GCS is
  # enabled in audit.tf.

  labels = {
    data_class = "customer-data"
  }

  depends_on = [google_kms_crypto_key_iam_member.storage_analytics]
}

# --- The analytics store ---

resource "google_bigquery_dataset" "analytics" {
  dataset_id  = "measurements"
  location    = var.gcp_region
  description = "Synthetic customer measurements, loaded from the AWS extract. Reconstructible rather than restorable -- see KSI-RPL-RRO."

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.analytics.id
  }

  # KSI-SVC-SIN build row 5: dataset IAM bound to declared roles only, no
  # primitive roles. `access` blocks here replace the default set, which
  # would otherwise include the project's legacy owner/editor/viewer
  # bindings -- those are the primitive roles the build row bars, and they
  # are present by default rather than by declaration, which is also what
  # KSI-CNA-DFP is written to catch.
  access {
    role          = "roles/bigquery.dataOwner"
    user_by_email = "terraform-admin@${var.gcp_project_id}.iam.gserviceaccount.com"
  }

  access {
    role          = "roles/bigquery.dataEditor"
    user_by_email = google_service_account.pipeline.email
  }

  # Tables are dropped and reloaded by the pipeline rather than mutated,
  # which is the analytics-side analogue of KSI-CMT-RMV's redeploy-rather-
  # than-modify position.
  delete_contents_on_destroy = true

  labels = {
    data_class = "customer-data"
  }

  depends_on = [google_kms_crypto_key_iam_member.bigquery_analytics]
}

resource "google_bigquery_table" "measurements" {
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  table_id   = "measurements"

  deletion_protection = false # this environment is meant to be rebuilt

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.analytics.id
  }

  # Partitioned on the measurement time so a query for one day scans one
  # day. The same reasoning as the log corpus's partition projection on the
  # AWS side: the cost control is structural rather than a spend alarm.
  time_partitioning {
    type  = "DAY"
    field = "recorded_at"
    # 90 days (2026-10-03, the lean retention set). The warehouse is the
    # only copy of a measurement past 30 days -- extracts expire then and
    # the database is rebuilt every session -- so this is a retention
    # decision, not housekeeping.
    expiration_ms = 7776000000
  }

  clustering = ["customer"]

  # Declared explicitly rather than autodetected on load. An autodetected
  # schema changes silently when the source changes, which would make
  # KSI-SVC-ACM's drift question unanswerable for the one resource whose
  # shape is set by data rather than by code.
  schema = jsonencode([
    {
      name        = "id"
      type        = "INTEGER"
      mode        = "REQUIRED"
      description = "Primary key from the source table. The deduplication key -- landings are at-least-once."
    },
    {
      name = "customer"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "metric"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "value"
      type = "NUMERIC"
      mode = "REQUIRED"
    },
    {
      name = "recorded_at"
      type = "TIMESTAMP"
      mode = "REQUIRED"
    },
  ])

  labels = {
    data_class = "customer-data"
  }
}

# --- The registry ---

resource "google_artifact_registry_repository" "pipeline" {
  repository_id = "fedramp-20x-ksi"
  location      = var.gcp_region
  format        = "DOCKER"
  description   = "Images for the analytics pipeline job."

  kms_key_name = google_kms_crypto_key.artifacts.id

  docker_config {
    # KSI-SVC-VRI build row 4, the GCP half. Once a tag points at a digest
    # it cannot be moved.
    immutable_tags = true
  }

  # Keep the five most recent images; delete others once 30 days old
  # (2026-10-03, the lean retention set). The pinned digest in pipeline.tf
  # must survive, which a recent build always does; svc-vri-ops-gcp-pinned-
  # image-present fails the same day if it ever does not.
  #
  # Live since 2026-10-07. It ran in dry run from 2026-10-03, but a dry run
  # logs only what qualifies, and nothing does before 2026-10-31, when the
  # oldest image turns 30 days old. So the review was of the policy against
  # the versions instead (DECISIONS.md, 2026-10-07): each build is four
  # versions, the latest build -- the pinned one -- is kept whole, and the
  # two older builds are what would go.
  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "keep-five-most-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 5
    }
  }

  cleanup_policies {
    id     = "delete-older-than-30-days"
    action = "DELETE"

    condition {
      tag_state  = "ANY"
      older_than = "2592000s"
    }
  }

  depends_on = [
    google_project_service.analytics,
    google_kms_crypto_key_iam_member.artifactregistry_artifacts,
  ]
}
