# The analytics pipeline, and the cross-cloud identity it runs as.
#
# This is the single machine-to-machine cross-cloud path in the
# architecture, and KSI-SVC-VCM is determined against it. The job runs on a
# schedule, reaches into the AWS extract bucket, lands what it finds in GCS,
# and loads it into BigQuery.
#
# The direction matters. GCP reaches into AWS, not the reverse, so there is
# one federation to establish rather than two, and the AWS side holds no
# Google credential. KSI-IAM-SNU's durability hierarchy applies unchanged:
# no static key exists on either end. The job presents a Google-issued
# identity token and AWS exchanges it for a short-lived session, which is
# the same mechanism the GitHub pipeline uses, with a different issuer.

# --- The pipeline's identity ---

resource "google_service_account" "pipeline" {
  account_id   = "analytics-pipeline"
  display_name = "Analytics pipeline job"
  description  = "Runs the scheduled analytics load. Federates to AWS to read the extract bucket."
}

# Least privilege, stated per role rather than granted at project level.
# KSI-CNA-DFP build row 2 bars predefined roles on workload identities in
# favour of explicit enumeration -- but GCP has no practical equivalent of
# an inline IAM policy for service identities, so the honest position is
# narrow predefined roles scoped to single resources, with the difference
# from the AWS side declared rather than papered over.
#
# The job writes each load as a new, timestamped object and BigQuery's load
# job reads it back as the job's identity: create and read, nothing more.
# Until 2026-10-05 this was storage.objectAdmin, which also overwrites,
# deletes and sets object ACLs; the policy gate's scanner found it (Trivy
# GCP-0007, KSI-MLA-EVC).
resource "google_storage_bucket_iam_member" "pipeline_landing_write" {
  bucket = google_storage_bucket.landing.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.pipeline.email}"
}

resource "google_storage_bucket_iam_member" "pipeline_landing_read" {
  bucket = google_storage_bucket.landing.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.pipeline.email}"
}

# The job creates load jobs, which is a project-level capability rather
# than a dataset-level one. Dataset write access is granted separately in
# the dataset's own access block.
resource "google_project_iam_member" "pipeline_bigquery_jobs" {
  project = var.gcp_project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.pipeline.email}"
}

resource "google_kms_crypto_key_iam_member" "pipeline_analytics" {
  crypto_key_id = google_kms_crypto_key.analytics.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.pipeline.email}"
}

# --- The job ---
#
# Gated the same way the AWS services are, and for the same reason:
# KSI-SVC-VRI requires the image be referenced by digest, and a digest
# cannot be looked up for an image that has not been built. With no image
# the rest of this root still applies.
variable "deploy_pipeline" {
  description = "Create the Cloud Run job. Requires an image already pushed to the Artifact Registry repository."
  type        = bool
  # On since 2026-10-02: the analytics image exists, built and signed by
  # build-and-push.yml. Declared here rather than passed at apply, so the
  # collector's CI plan of this root sees the job as declared, not as
  # something to destroy.
  default = true
}

variable "pipeline_image" {
  description = "Fully qualified image reference for the pipeline job, pinned by digest (repo@sha256:...)."
  type        = string
  # The deployed image, by digest, as a reviewed declaration: changing what
  # runs is a commit. This digest is build run 37066486575's, tag
  # git-0cee46bbabef, signed and verified in that run: the MERGE on
  # (id, recorded_at) (DECISIONS.md, 2026-10-02). It replaced build run
  # 36954218125's (git-193454c1a7b2), which merged on id alone.
  default = "us-central1-docker.pkg.dev/fedramp-20x-ksi-assessment/fedramp-20x-ksi/analytics@sha256:6db759e5a6afc66c1059896ec64b8706434b5f034856e56406887568cf63e79e"

  validation {
    # A tag reference is the mutable pointer KSI-SVC-VRI exists to reject.
    # Caught here rather than at deploy time, because a tag that resolves
    # today and something else tomorrow is exactly the failure the
    # indicator is about.
    condition     = var.pipeline_image == "" || can(regex("@sha256:[0-9a-f]{64}$", var.pipeline_image))
    error_message = "pipeline_image must be pinned by digest (ending @sha256:<64 hex>), never by tag."
  }
}

variable "aws_extract_bucket" {
  description = "Name of the AWS S3 bucket holding measurement extracts."
  type        = string
  default     = "fedramp-20x-ksi-extracts-437672023758"
}

variable "aws_extract_role_arn" {
  description = "AWS role the pipeline assumes to read the extract bucket. Created by the aws root; see infra/aws/cross_cloud.tf."
  type        = string
  default     = "arn:aws:iam::437672023758:role/fedramp-20x-ksi-gcp-pipeline"
}

resource "google_cloud_run_v2_job" "pipeline" {
  count = var.deploy_pipeline ? 1 : 0

  name     = "analytics-pipeline"
  location = var.gcp_region

  deletion_protection = false

  template {
    template {
      service_account = google_service_account.pipeline.email

      # One attempt plus two retries, then the execution fails and the
      # alarm fires. Infinite retry would hide a job that never succeeds.
      max_retries = 2
      timeout     = "900s"

      containers {
        image = var.pipeline_image

        # Stated rather than inherited from the image, per KSI-CNA-DFP
        # build row 1 -- the same discipline the ECS task definitions
        # follow on the AWS side.
        command = ["python"]
        args    = ["main.py"]

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "GCP_PROJECT"
          value = var.gcp_project_id
        }
        env {
          name  = "LANDING_BUCKET"
          value = google_storage_bucket.landing.name
        }
        env {
          name  = "BQ_DATASET"
          value = google_bigquery_dataset.analytics.dataset_id
        }
        env {
          name  = "BQ_TABLE"
          value = google_bigquery_table.measurements.table_id
        }
        env {
          name  = "KMS_KEY"
          value = google_kms_crypto_key.analytics.id
        }
        env {
          name  = "AWS_EXTRACT_BUCKET"
          value = var.aws_extract_bucket
        }
        env {
          name  = "AWS_ROLE_ARN"
          value = var.aws_extract_role_arn
        }
        # The audience the identity token must carry. This has to equal
        # what the AWS trust policy pins accounts.google.com:aud to, which
        # is this service account's numeric unique ID -- not its email.
        # Passed explicitly rather than derived in the job, because the
        # two values must agree across two roots and a derivation that
        # drifts from the policy fails only at run time.
        env {
          name  = "GCP_SA_UNIQUE_ID"
          value = google_service_account.pipeline.unique_id
        }
        env {
          name  = "AWS_REGION"
          value = "us-east-1"
        }
      }
    }
  }

  depends_on = [google_project_service.analytics]
}

# --- The schedule ---
#
# The same limitation the AWS collector cadence carries: this is a real
# schedule, managed by Terraform, and it therefore exists only while the
# environment does. A production deployment would run continuously.
# Recorded rather than implied.
resource "google_service_account" "scheduler" {
  account_id   = "pipeline-scheduler"
  display_name = "Invokes the analytics pipeline job"
  description  = "Holds only the right to run one job. Separate from the job's own identity."
}

# The invoker is a separate identity from the job, so that the right to
# *start* the pipeline is not the same as the right to *be* the pipeline.
# Compromising the schedule gives an attacker a job run, not the job's
# access to the extract bucket and the dataset.
resource "google_cloud_run_v2_job_iam_member" "scheduler_invoke" {
  count = var.deploy_pipeline ? 1 : 0

  name     = google_cloud_run_v2_job.pipeline[0].name
  location = google_cloud_run_v2_job.pipeline[0].location
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "pipeline" {
  count = var.deploy_pipeline ? 1 : 0

  name        = "analytics-pipeline"
  region      = var.gcp_region
  description = "Runs the analytics load every six hours."

  # Six-hourly. The AWS worker extracts every fifteen minutes into S3, so
  # this batches several extracts per run rather than racing them.
  schedule  = "0 */6 * * *"
  time_zone = "Etc/UTC"

  attempt_deadline = "320s"

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = "https://${var.gcp_region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.gcp_project_id}/jobs/${google_cloud_run_v2_job.pipeline[0].name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.analytics]
}

output "pipeline_service_account_email" {
  description = "The pipeline's identity. The AWS cross-cloud role trusts this."
  value       = google_service_account.pipeline.email
}

output "pipeline_service_account_unique_id" {
  description = <<-EOT
    Numeric unique ID of the pipeline service account.

    This is what the AWS trust policy matches on, not the email: an email
    can be deleted and recreated, and the recreated account would inherit
    trust it was never granted. The numeric ID never repeats.

    Set as TF_VAR_gcp_pipeline_sa_unique_id when applying the aws root.
  EOT
  value       = google_service_account.pipeline.unique_id
}

output "artifact_registry_repository" {
  description = "Where the pipeline image is pushed."
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.pipeline.repository_id}"
}
