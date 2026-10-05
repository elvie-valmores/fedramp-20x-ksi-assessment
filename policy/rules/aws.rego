# Authored rules for the AWS roots. Each encodes a determination; the
# mapping, with severity, is policy/coverage.yaml.
package fedramp.policy

import rego.v1

# AWS-S3-01 (KSI-CNA-MAT): every bucket has a public access block, and
# every block sets all four switches.
violations contains violation("AWS-S3-01", b, "bucket has no public access block") if {
	some b in of_type("aws_s3_bucket")
	count(referencing("aws_s3_bucket_public_access_block", "bucket", config_address(b))) == 0
}

violations contains violation("AWS-S3-01", r, sprintf("public access block leaves %s off", [k])) if {
	some r in of_type("aws_s3_bucket_public_access_block")
	some k in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	r.change.after[k] != true
}

# AWS-S3-02 (KSI-SVC-SIN): every bucket is encrypted, with a customer key.
violations contains violation("AWS-S3-02", b, "bucket has no encryption configuration") if {
	some b in of_type("aws_s3_bucket")
	count(referencing("aws_s3_bucket_server_side_encryption_configuration", "bucket", config_address(b))) == 0
}

violations contains violation("AWS-S3-02", r, sprintf("encrypted with %s, not a customer key", [d.sse_algorithm])) if {
	some r in of_type("aws_s3_bucket_server_side_encryption_configuration")
	some rule in r.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm != "aws:kms"
}

violations contains violation("AWS-S3-02", r, "aws:kms with no key named: the AWS-managed key") if {
	some r in of_type("aws_s3_bucket_server_side_encryption_configuration")
	some i, rule in r.change.after.rule
	some j, d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm == "aws:kms"
	object.get(d, "kms_master_key_id", "") == ""
	not r.change.after_unknown.rule[i].apply_server_side_encryption_by_default[j].kms_master_key_id
}

# AWS-S3-03 (KSI-SVC-PRR): every bucket has a lifecycle, so nothing it
# holds is kept without an expiry.
violations contains violation("AWS-S3-03", b, "bucket has no lifecycle configuration") if {
	some b in of_type("aws_s3_bucket")
	count(referencing("aws_s3_bucket_lifecycle_configuration", "bucket", config_address(b))) == 0
}

# AWS-KMS-01 (KSI-SVC-SIN): every customer key rotates.
violations contains violation("AWS-KMS-01", r, "key rotation is off") if {
	some r in of_type("aws_kms_key")
	r.change.after.enable_key_rotation != true
}

# AWS-LOG-01 (KSI-MLA-LET, KSI-SVC-PRR): every log group expires within
# 90 days and is under a customer key.
violations contains violation("AWS-LOG-01", r, "log group never expires") if {
	some r in of_type("aws_cloudwatch_log_group")
	object.get(r.change.after, "retention_in_days", 0) == 0
}

violations contains violation("AWS-LOG-01", r, sprintf("log group kept %d days, over 90", [r.change.after.retention_in_days])) if {
	some r in of_type("aws_cloudwatch_log_group")
	r.change.after.retention_in_days > 90
}

violations contains violation("AWS-LOG-01", r, "log group has no customer key") if {
	some r in of_type("aws_cloudwatch_log_group")
	object.get(r.change.after, "kms_key_id", null) == null
	not unknown(r, "kms_key_id")
}

# AWS-NET-01 (KSI-CNA-RNT): the internet reaches only the load balancer,
# and only on 80 (which redirects) and 443.
open_cidrs := {"0.0.0.0/0", "::/0"}

violations contains violation("AWS-NET-01", r, sprintf("open ingress on %v-%v", [r.change.after.from_port, r.change.after.to_port])) if {
	some r in of_type("aws_vpc_security_group_ingress_rule")
	some k in ["cidr_ipv4", "cidr_ipv6"]
	r.change.after[k] in open_cidrs
	not open_ingress_allowed(r)
}

open_ingress_allowed(r) if {
	c := [c | some c in config_resources; c.address == config_address(r)][0]
	"aws_security_group.alb" in c.expressions.security_group_id.references
	r.change.after.from_port == r.change.after.to_port
	r.change.after.from_port in {80, 443}
}

violations contains violation("AWS-NET-01", r, "security group with an inline open ingress rule") if {
	some r in of_type("aws_security_group")
	some rule in object.get(r.change.after, "ingress", [])
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
}

# AWS-NET-02 (KSI-CNA-RNT): no egress to anywhere. Every flow names its
# destination (registers/flows.yaml).
violations contains violation("AWS-NET-02", r, "open egress") if {
	some r in of_type("aws_vpc_security_group_egress_rule")
	some k in ["cidr_ipv4", "cidr_ipv6"]
	r.change.after[k] in open_cidrs
}

violations contains violation("AWS-NET-02", r, "security group with an inline open egress rule") if {
	some r in of_type("aws_security_group")
	some rule in object.get(r.change.after, "egress", [])
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
}

# AWS-IAM-01 (KSI-CNA-DFP): workload roles carry enumerated policies, never
# an AWS-managed one (2026-09-05).
violations contains violation("AWS-IAM-01", r, sprintf("AWS-managed policy %s on a role", [r.change.after.policy_arn])) if {
	some r in of_type("aws_iam_role_policy_attachment")
	startswith(r.change.after.policy_arn, "arn:aws:iam::aws:policy/")
}

violations contains violation("AWS-IAM-01", r, "managed_policy_arns on a role") if {
	some r in of_type("aws_iam_role")
	count(object.get(r.change.after, "managed_policy_arns", [])) > 0
}

# AWS-IAM-02 (KSI-IAM-SNU): a role federated to an outside identity
# provider pins both the audience and the subject.
violations contains violation("AWS-IAM-02", r, sprintf("web-identity trust does not pin %s", [k])) if {
	some r in of_type("aws_iam_role")
	not unknown(r, "assume_role_policy")
	doc := json.unmarshal(r.change.after.assume_role_policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
	"sts:AssumeRoleWithWebIdentity" in as_array(st.Action)
	some k in [":aud", ":sub"]
	not pins(st, k)
}

pins(st, suffix) if {
	some op in ["StringEquals", "StringLike"]
	some key, _ in st.Condition[op]
	endswith(key, suffix)
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# AWS-IAM-03 (KSI-IAM-SNU): no IAM users and no access keys. People sign in
# through Identity Center; workloads federate.
violations contains violation("AWS-IAM-03", r, sprintf("%s declared", [r.type])) if {
	some r in resources
	r.type in {"aws_iam_user", "aws_iam_access_key", "aws_iam_user_login_profile"}
}

# AWS-RDS-01 (KSI-SVC-SIN, KSI-CNA-RNT): the database is encrypted, private
# and authenticates by IAM.
violations contains violation("AWS-RDS-01", r, sprintf("%s is %v", [k, r.change.after[k]])) if {
	some r in of_type("aws_db_instance")
	some k, want in {"storage_encrypted": true, "publicly_accessible": false, "iam_database_authentication_enabled": true}
	r.change.after[k] != want
}

# AWS-ECR-01 (KSI-SVC-VRI): image tags are immutable and every push is scanned.
violations contains violation("AWS-ECR-01", r, "tags are mutable") if {
	some r in of_type("aws_ecr_repository")
	r.change.after.image_tag_mutability != "IMMUTABLE"
}

violations contains violation("AWS-ECR-01", r, "scan on push is off") if {
	some r in of_type("aws_ecr_repository")
	not scans_on_push(r)
}

scans_on_push(r) if r.change.after.image_scanning_configuration[0].scan_on_push == true

# AWS-LB-01 (KSI-SVC-VCM): a plain HTTP listener only redirects.
violations contains violation("AWS-LB-01", r, "HTTP listener does something other than redirect") if {
	some r in of_type("aws_lb_listener")
	r.change.after.protocol == "HTTP"
	some a in r.change.after.default_action
	a.type != "redirect"
}

# AWS-SSO-01 (KSI-IAM-JIT, KSI-CNA-ULN): no sign-in lasts over four hours,
# and an administrator's over one.
violations contains violation("AWS-SSO-01", r, sprintf("session %s, over PT4H", [r.change.after.session_duration])) if {
	some r in of_type("aws_ssoadmin_permission_set")
	duration_seconds(r.change.after.session_duration) > 14400
}

violations contains violation("AWS-SSO-01", r, sprintf("administrator session %s, over PT1H", [r.change.after.session_duration])) if {
	some r in of_type("aws_ssoadmin_permission_set")
	duration_seconds(r.change.after.session_duration) > 3600
	some a in of_type("aws_ssoadmin_managed_policy_attachment")
	a.change.after.managed_policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
	attachment := [c | some c in config_resources; c.address == config_address(a)][0]
	config_address(r) in attachment.expressions.permission_set_arn.references
}
