provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region

  # Terraform authenticates as the human running it (via Application
  # Default Credentials, `gcloud auth application-default login`), then
  # impersonates this service account for every real API call. No static
  # key file — closer to how AWS SSO/assumed-role setups work than to a
  # long-lived access key.
  impersonate_service_account = "terraform-admin@${var.gcp_project_id}.iam.gserviceaccount.com"
}
