# Looks up the project this root manages.
#
# Needed because several resources want the project's *number*, which is
# assigned by GCP and differs from the human-readable project ID. Defined
# once here rather than repeated per file.
data "google_project" "current" {
  project_id = var.gcp_project_id
}
