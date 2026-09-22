provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region

  # Auth happens in two hops: Terraform authenticates as whoever is
  # running it (Application Default Credentials, written by
  # `gcloud auth application-default login`), then mints a short-lived
  # token for this service account and acts as it.
  #
  # The point is that no service account key file exists to be leaked.
  # inventory/gcp_auth.py does the same thing for the Python tooling, so
  # both act as the same identity.
  impersonate_service_account = "terraform-admin@${var.gcp_project_id}.iam.gserviceaccount.com"
}

# Same identity and the same two-hop auth as above. Declared separately
# because a provider block cannot be shared between two providers, not
# because anything about the authentication differs.
provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region

  impersonate_service_account = "terraform-admin@${var.gcp_project_id}.iam.gserviceaccount.com"
}
