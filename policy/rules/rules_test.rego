# Negative controls for every authored rule: an input that must be flagged,
# beside one that must not. `opa test policy/rules` runs them in CI.
package fedramp.policy_test

import rego.v1

import data.fedramp.policy

rc(type, name, after) := {"address": sprintf("%s.%s", [type, name]), "mode": "managed", "type": type, "change": {"actions": ["create"], "after": after, "after_unknown": {}}}

cfg(type, name, expressions) := {"address": sprintf("%s.%s", [type, name]), "type": type, "expressions": expressions}

plan(changes, configs) := {"resource_changes": changes, "configuration": {"root_module": {"resources": configs}}}

rules_hit(p) := {v.rule | some v in policy.violations with input as p}

ref(t) := {"references": [sprintf("%s.id", [t]), t]}

pab_ok := {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}

kms_sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:k"}]}]}

good_bucket := plan(
	[
		rc("aws_s3_bucket", "b", {}),
		rc("aws_s3_bucket_public_access_block", "b", pab_ok),
		rc("aws_s3_bucket_server_side_encryption_configuration", "b", kms_sse),
		rc("aws_s3_bucket_lifecycle_configuration", "b", {}),
	],
	[
		cfg("aws_s3_bucket_public_access_block", "b", {"bucket": ref("aws_s3_bucket.b")}),
		cfg("aws_s3_bucket_server_side_encryption_configuration", "b", {"bucket": ref("aws_s3_bucket.b")}),
		cfg("aws_s3_bucket_lifecycle_configuration", "b", {"bucket": ref("aws_s3_bucket.b")}),
	],
)

test_a_complete_bucket_passes if count(rules_hit(good_bucket)) == 0

test_a_bare_bucket_fails_all_three if {
	rules_hit(plan([rc("aws_s3_bucket", "b", {})], [])) == {"AWS-S3-01", "AWS-S3-02", "AWS-S3-03"}
}

test_a_partial_public_access_block_fails if {
	"AWS-S3-01" in rules_hit(plan([rc("aws_s3_bucket_public_access_block", "b", object.union(pab_ok, {"restrict_public_buckets": false}))], []))
}

test_sse_s3_fails if {
	"AWS-S3-02" in rules_hit(plan([rc("aws_s3_bucket_server_side_encryption_configuration", "b", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})], []))
}

test_the_aws_managed_key_fails if {
	"AWS-S3-02" in rules_hit(plan([rc("aws_s3_bucket_server_side_encryption_configuration", "b", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": ""}]}]})], []))
}

test_a_deleted_bucket_is_not_judged if {
	gone := json.patch(rc("aws_s3_bucket", "b", {}), [{"op": "replace", "path": "/change/actions", "value": ["delete"]}])
	count(rules_hit(plan([gone], []))) == 0
}

test_key_without_rotation_fails if {
	rules_hit(plan([rc("aws_kms_key", "k", {"enable_key_rotation": false})], [])) == {"AWS-KMS-01"}
	count(rules_hit(plan([rc("aws_kms_key", "k", {"enable_key_rotation": true})], []))) == 0
}

test_log_groups if {
	count(rules_hit(plan([rc("aws_cloudwatch_log_group", "l", {"retention_in_days": 30, "kms_key_id": "k"})], []))) == 0
	"AWS-LOG-01" in rules_hit(plan([rc("aws_cloudwatch_log_group", "l", {"retention_in_days": 0, "kms_key_id": "k"})], []))
	"AWS-LOG-01" in rules_hit(plan([rc("aws_cloudwatch_log_group", "l", {"retention_in_days": 365, "kms_key_id": "k"})], []))
	"AWS-LOG-01" in rules_hit(plan([rc("aws_cloudwatch_log_group", "l", {"retention_in_days": 30, "kms_key_id": null})], []))
}

open_rule(sg, port) := plan(
	[rc("aws_vpc_security_group_ingress_rule", "r", {"cidr_ipv4": "0.0.0.0/0", "from_port": port, "to_port": port})],
	[cfg("aws_vpc_security_group_ingress_rule", "r", {"security_group_id": ref(sg)})],
)

test_open_ingress_only_to_the_load_balancer_on_web_ports if {
	count(rules_hit(open_rule("aws_security_group.alb", 443))) == 0
	count(rules_hit(open_rule("aws_security_group.alb", 80))) == 0
	"AWS-NET-01" in rules_hit(open_rule("aws_security_group.alb", 22))
	"AWS-NET-01" in rules_hit(open_rule("aws_security_group.database", 443))
	"AWS-NET-01" in rules_hit(plan([rc("aws_security_group", "s", {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]})], []))
}

test_open_egress_fails if {
	"AWS-NET-02" in rules_hit(plan([rc("aws_vpc_security_group_egress_rule", "e", {"cidr_ipv4": "0.0.0.0/0"})], []))
	"AWS-NET-02" in rules_hit(plan([rc("aws_vpc_security_group_egress_rule", "e", {"cidr_ipv6": "::/0"})], []))
	count(rules_hit(plan([rc("aws_vpc_security_group_egress_rule", "e", {"cidr_ipv4": "10.0.0.0/16"})], []))) == 0
}

test_aws_managed_policy_on_a_role_fails if {
	"AWS-IAM-01" in rules_hit(plan([rc("aws_iam_role_policy_attachment", "a", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})], []))
	count(rules_hit(plan([rc("aws_iam_role_policy_attachment", "a", {"policy_arn": "arn:aws:iam::1:policy/mine"})], []))) == 0
}

trust(conditions) := json.marshal({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Condition": conditions}]})

test_web_identity_trust_pins_audience_and_subject if {
	pinned := {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": "repo:o/r:ref:refs/heads/main"}}
	count(rules_hit(plan([rc("aws_iam_role", "r", {"assume_role_policy": trust(pinned)})], []))) == 0
	"AWS-IAM-02" in rules_hit(plan([rc("aws_iam_role", "r", {"assume_role_policy": trust({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})})], []))
	"AWS-IAM-02" in rules_hit(plan([rc("aws_iam_role", "r", {"assume_role_policy": trust({})})], []))
}

test_iam_users_and_keys_fail if {
	"AWS-IAM-03" in rules_hit(plan([rc("aws_iam_user", "u", {})], []))
	"AWS-IAM-03" in rules_hit(plan([rc("aws_iam_access_key", "k", {})], []))
}

db(changes) := plan([rc("aws_db_instance", "d", object.union({"storage_encrypted": true, "publicly_accessible": false, "iam_database_authentication_enabled": true}, changes))], [])

test_database_settings if {
	count(rules_hit(db({}))) == 0
	"AWS-RDS-01" in rules_hit(db({"publicly_accessible": true}))
	"AWS-RDS-01" in rules_hit(db({"storage_encrypted": false}))
	"AWS-RDS-01" in rules_hit(db({"iam_database_authentication_enabled": false}))
}

test_registry_settings if {
	count(rules_hit(plan([rc("aws_ecr_repository", "r", {"image_tag_mutability": "IMMUTABLE", "image_scanning_configuration": [{"scan_on_push": true}]})], []))) == 0
	"AWS-ECR-01" in rules_hit(plan([rc("aws_ecr_repository", "r", {"image_tag_mutability": "MUTABLE", "image_scanning_configuration": [{"scan_on_push": true}]})], []))
	"AWS-ECR-01" in rules_hit(plan([rc("aws_ecr_repository", "r", {"image_tag_mutability": "IMMUTABLE", "image_scanning_configuration": []})], []))
}

test_http_listener_must_redirect if {
	count(rules_hit(plan([rc("aws_lb_listener", "l", {"protocol": "HTTP", "default_action": [{"type": "redirect"}]})], []))) == 0
	"AWS-LB-01" in rules_hit(plan([rc("aws_lb_listener", "l", {"protocol": "HTTP", "default_action": [{"type": "forward"}]})], []))
}

admin_set(duration) := plan(
	[
		rc("aws_ssoadmin_permission_set", "p", {"session_duration": duration}),
		rc("aws_ssoadmin_managed_policy_attachment", "a", {"managed_policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
	],
	[cfg("aws_ssoadmin_managed_policy_attachment", "a", {"permission_set_arn": {"references": ["aws_ssoadmin_permission_set.p.arn", "aws_ssoadmin_permission_set.p"]}})],
)

test_session_bounds if {
	count(rules_hit(admin_set("PT1H"))) == 0
	"AWS-SSO-01" in rules_hit(admin_set("PT2H"))
	count(rules_hit(plan([rc("aws_ssoadmin_permission_set", "p", {"session_duration": "PT4H"})], []))) == 0
	"AWS-SSO-01" in rules_hit(plan([rc("aws_ssoadmin_permission_set", "p", {"session_duration": "PT8H"})], []))
	"AWS-SSO-01" in rules_hit(plan([rc("aws_ssoadmin_permission_set", "p", {"session_duration": "PT4H30M"})], []))
}

gcs(changes) := plan([rc("google_storage_bucket", "b", object.union({"uniform_bucket_level_access": true, "public_access_prevention": "enforced", "encryption": [{"default_kms_key_name": "k"}]}, changes))], [])

test_gcs_bucket_settings if {
	count(rules_hit(gcs({}))) == 0
	"GCP-GCS-01" in rules_hit(gcs({"uniform_bucket_level_access": false}))
	"GCP-GCS-01" in rules_hit(gcs({"public_access_prevention": "inherited"}))
	"GCP-GCS-01" in rules_hit(gcs({"encryption": []}))
}

test_dataset_needs_a_customer_key if {
	count(rules_hit(plan([rc("google_bigquery_dataset", "d", {"default_encryption_configuration": [{"kms_key_name": "k"}]})], []))) == 0
	"GCP-BQ-01" in rules_hit(plan([rc("google_bigquery_dataset", "d", {"default_encryption_configuration": []})], []))
}

test_basic_roles_fail if {
	"GCP-IAM-01" in rules_hit(plan([rc("google_project_iam_member", "m", {"role": "roles/editor"})], []))
	"GCP-IAM-01" in rules_hit(plan([rc("google_storage_bucket_iam_binding", "m", {"role": "roles/owner"})], []))
	count(rules_hit(plan([rc("google_project_iam_member", "m", {"role": "roles/bigquery.jobUser"})], []))) == 0
}

test_service_account_keys_fail if "GCP-IAM-02" in rules_hit(plan([rc("google_service_account_key", "k", {})], []))

job(image) := plan([rc("google_cloud_run_v2_job", "j", {"template": [{"template": [{"containers": [{"image": image}]}]}]})], [])

test_job_image_by_digest if {
	count(rules_hit(job("r/analytics@sha256:abc"))) == 0
	"GCP-RUN-01" in rules_hit(job("r/analytics:latest"))
}

test_gcp_key_rotation if {
	count(rules_hit(plan([rc("google_kms_crypto_key", "k", {"rotation_period": "31536000s"})], []))) == 0
	"GCP-KMS-01" in rules_hit(plan([rc("google_kms_crypto_key", "k", {"rotation_period": "63072000s"})], []))
	"GCP-KMS-01" in rules_hit(plan([rc("google_kms_crypto_key", "k", {})], []))
}
