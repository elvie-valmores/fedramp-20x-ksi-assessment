# Secret material, and the certificates.
#
# KSI-SVC-ASM's build row 1: managed secret storage, no secrets in
# environment variables or task definitions, injection by reference at
# runtime. The task definitions in compute.tf pass secret *ARNs* as
# environment variables and the application fetches the material itself --
# so a `describe-task-definition` call, which any read-only principal can
# make, reveals where the secret lives and not what it is.
#
# There are only two secrets in this environment, and neither is a password
# the application holds:
#
#   - the task TLS certificate and key, which the api serves
#   - the database master password, which RDS generates and manages and
#     only the one-off migration task ever reads
#
# The application's own database credential is an IAM auth token minted per
# connection, so it is never stored anywhere at all. That is the strongest
# form of KSI-SVC-ASM's claim available: the secret that does not exist
# needs no rotation.

# --- The task certificate ---
#
# KSI-SVC-SIN's build row 2 requires TLS continue to the task rather than
# terminate at the load balancer. That needs a certificate the task can
# serve.
#
# This is a self-signed certificate rather than an ACM-issued one, and the
# reason is a hard constraint rather than a preference: ACM issues public
# certificates only after validating control of a domain name, and this
# persona owns no domain. AWS Private CA would issue a real internal
# certificate and costs roughly 400 USD per month, which is more than three
# times the entire environment's standing cost.
#
# What is lost is stated rather than glossed: KSI-SVC-ASM's build row 4
# wants ACM-issued certificates with automatic renewal, and a self-signed
# certificate has neither a chain of trust nor managed renewal. Recorded in
# docs/DECISIONS.md.
resource "tls_private_key" "task" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "task" {
  private_key_pem = tls_private_key.task.private_key_pem

  subject {
    common_name  = "api.fedramp-20x-ksi.internal"
    organization = "fedramp-20x-ksi-assessment"
  }

  # One year. Short enough that renewal is a real operation rather than a
  # theoretical one, long enough not to expire mid-assessment.
  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = ["api.fedramp-20x-ksi.internal"]
}

resource "aws_secretsmanager_secret" "task_tls" {
  name        = "fedramp-20x-ksi/task-tls"
  description = "Certificate and key the api task serves on the internal hop"
  kms_key_id  = aws_kms_key.secrets.arn

  # Zero, meaning delete immediately with no recovery window.
  #
  # The instinct is to set seven days as a safety net against a mistaken
  # destroy. That instinct is wrong here and would break the next session:
  # a scheduled-for-deletion secret still holds its name, so the following
  # `terraform apply` fails with InvalidRequestException rather than
  # recreating it. In an environment destroyed deliberately every session,
  # a recovery window is a guaranteed blocker rather than a safety net.
  #
  # Nothing is lost. The secret holds a certificate this configuration
  # regenerates from scratch on every apply.
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "task_tls" {
  secret_id = aws_secretsmanager_secret.task_tls.id

  secret_string = jsonencode({
    certificate = tls_self_signed_cert.task.cert_pem
    private_key = tls_private_key.task.private_key_pem
  })
}

# The load balancer needs the same certificate in ACM to terminate the
# public side. Imported rather than issued, for the reason above.
resource "aws_acm_certificate" "public" {
  private_key      = tls_private_key.task.private_key_pem
  certificate_body = tls_self_signed_cert.task.cert_pem

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "fedramp-20x-ksi-public"
  }
}
