# Authored rules for the GCP root. The mapping is policy/coverage.yaml.
package fedramp.policy

import rego.v1

# GCP-GCS-01 (KSI-SVC-SIN, KSI-CNA-MAT): every bucket is private, uniform
# and under a customer key.
violations contains violation("GCP-GCS-01", r, "uniform bucket-level access is off") if {
	some r in of_type("google_storage_bucket")
	r.change.after.uniform_bucket_level_access != true
}

violations contains violation("GCP-GCS-01", r, "public access prevention is not enforced") if {
	some r in of_type("google_storage_bucket")
	r.change.after.public_access_prevention != "enforced"
}

violations contains violation("GCP-GCS-01", r, "no customer key") if {
	some r in of_type("google_storage_bucket")
	not gcs_cmek(r)
}

gcs_cmek(r) if r.change.after.encryption[0].default_kms_key_name != ""

gcs_cmek(r) if r.change.after_unknown.encryption[0].default_kms_key_name == true

# GCP-BQ-01 (KSI-SVC-SIN): every dataset defaults to a customer key.
violations contains violation("GCP-BQ-01", r, "dataset has no default customer key") if {
	some r in of_type("google_bigquery_dataset")
	not bq_cmek(r)
}

bq_cmek(r) if r.change.after.default_encryption_configuration[0].kms_key_name != ""

bq_cmek(r) if r.change.after_unknown.default_encryption_configuration[0].kms_key_name == true

# GCP-IAM-01 (KSI-IAM-ELP): no basic role is granted by declaration.
basic_roles := {"roles/owner", "roles/editor", "roles/viewer"}

violations contains violation("GCP-IAM-01", r, sprintf("basic role %s granted", [r.change.after.role])) if {
	some r in resources
	startswith(r.type, "google_")
	regex.match(`_iam_(member|binding)$`, r.type)
	r.change.after.role in basic_roles
}

# GCP-IAM-02 (KSI-IAM-SNU): no service account keys. Workloads federate.
violations contains violation("GCP-IAM-02", r, "service account key declared") if {
	some r in of_type("google_service_account_key")
}

# GCP-RUN-01 (KSI-SVC-VRI): the job runs an image by digest.
violations contains violation("GCP-RUN-01", r, sprintf("image %s is not pinned by digest", [c.image])) if {
	some r in of_type("google_cloud_run_v2_job")
	some t in r.change.after.template
	some tt in t.template
	some c in tt.containers
	not contains(c.image, "@sha256:")
}

# GCP-KMS-01 (KSI-SVC-SIN): every key rotates within a year.
violations contains violation("GCP-KMS-01", r, "no rotation period") if {
	some r in of_type("google_kms_crypto_key")
	object.get(r.change.after, "rotation_period", "") == ""
}

violations contains violation("GCP-KMS-01", r, sprintf("rotates every %s, over a year", [r.change.after.rotation_period])) if {
	some r in of_type("google_kms_crypto_key")
	to_number(trim_suffix(r.change.after.rotation_period, "s")) > 31536000
}
