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
# This certificate is self-signed, and the 2026-09-19 decision records why
# that is the right answer rather than a concession: the load balancer does
# not validate the certificate its targets present, and AWS documents that
# load-balancer-to-target traffic inside a VPC is authenticated at the packet
# level regardless. A trusted chain here would be verified by nothing in the
# path. Peer authenticity on this hop is established by platform identity
# under KSI-SVC-VCM, not by this certificate.
#
# It carries a one-year validity, and under apply-and-destroy it is
# regenerated whenever the environment is rebuilt. The seam is the same one
# the disclosure file's expiry carries: a deployment left standing for over a
# year without reapplying would serve an expired certificate. The mechanism
# is correct; the environment's uptime pattern is what bounds it.
#
# The load balancer's public certificate is a different certificate entirely
# and is ACM-issued -- see below.
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

# --- The load balancer's public certificate ---
#
# Two possible sources, and which one is used depends on whether a domain
# has been chosen.
#
# With a domain: the real certificate, issued by ACM through DNS validation
# and held in infra/bootstrap so that tearing this environment down does not
# destroy something a human validated by hand. Looked up rather than passed
# between roots, so the two stay decoupled.
#
# Without a domain: the self-signed certificate above, imported. This is the
# fallback the project ran on before a domain was available, kept so the
# environment remains applyable while the domain work is outstanding rather
# than blocking every apply on it.
data "aws_acm_certificate" "issued" {
  count = var.app_domain == "" ? 0 : 1

  domain   = var.app_domain
  statuses = ["ISSUED"]

  # Most recent, because renewal issues a new certificate alongside the old
  # one and both are ISSUED for a period.
  most_recent = true
}

resource "aws_acm_certificate" "public" {
  count = var.app_domain == "" ? 1 : 0

  private_key      = tls_private_key.task.private_key_pem
  certificate_body = tls_self_signed_cert.task.cert_pem

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "fedramp-20x-ksi-public-fallback"
  }
}

locals {
  # What the listener actually serves.
  listener_certificate_arn = (
    var.app_domain == ""
    ? aws_acm_certificate.public[0].arn
    : data.aws_acm_certificate.issued[0].arn
  )
}
