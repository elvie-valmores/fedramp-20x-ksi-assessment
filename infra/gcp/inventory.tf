# Cloud Asset Inventory -- GCP's equivalent of AWS Config, and the source
# the inventory generator queries; see inventory/gcp_source.py.
#
# The feed continuously reports resource changes to a Pub/Sub topic.
# Nothing subscribes to that topic yet; the feed's value right now is that
# it exists and is watching, which is itself the evidence. Queries go
# through the separate SearchAllResources API, which works regardless.
#
# Scoped to this project rather than an organization: the project sits
# outside any org, so project scope is the widest available -- and with
# one project, it is also complete. Recorded in docs/DECISIONS.md
# (2026-09-18).
#
# Unlike AWS Config, there is no per-item billing here, so no cost reason
# to narrow the type list. It is still required to be explicit: an empty
# asset_types list means "watch nothing", not "watch everything", and the
# API rejects a feed with neither types nor names. Keep in sync with
# ASSET_TYPES in inventory/gcp_source.py.
locals {
  asset_feed_types = [
    "storage.googleapis.com/Bucket",
    "run.googleapis.com/Service",
    "bigquery.googleapis.com/Dataset",
    "bigquery.googleapis.com/Table",
    "cloudkms.googleapis.com/CryptoKey",
    "artifactregistry.googleapis.com/Repository",
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/Role",
    "pubsub.googleapis.com/Topic",
    "cloudresourcemanager.googleapis.com/Project",
  ]
}

resource "google_pubsub_topic" "asset_feed" {
  name = "fedramp-20x-ksi-asset-feed"

  # The evidence key (analytics.tf), since 2026-10-01. Pub/Sub encrypts as
  # its own agent, so the agent's grant must exist before the topic uses
  # the key, or publishing fails.
  kms_key_name = google_kms_crypto_key.evidence.id

  depends_on = [google_kms_crypto_key_iam_member.pubsub_evidence]
}

# Cloud Asset Inventory publishes as its own Google-managed service
# account, not as terraform-admin, so that account needs its own grant on
# the topic. The address is derived from the project number and is fixed
# by Google's naming convention.
#
# It also has to be created before it can be granted anything -- see the
# gcloud beta services identity command in the setup notes; enabling the
# API alone does not create it.
resource "google_pubsub_topic_iam_member" "asset_feed_publisher" {
  topic  = google_pubsub_topic.asset_feed.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudasset.iam.gserviceaccount.com"
}

resource "google_cloud_asset_project_feed" "main" {
  project      = var.gcp_project_id
  feed_id      = "fedramp-20x-ksi-inventory-feed"
  content_type = "RESOURCE"
  asset_types  = local.asset_feed_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.asset_feed.id
    }
  }

  # The publish grant must exist first; GCP validates that the feed can
  # actually deliver to its destination at create time.
  depends_on = [google_pubsub_topic_iam_member.asset_feed_publisher]
}
