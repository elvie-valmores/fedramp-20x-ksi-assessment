# The application database.
#
# PostgreSQL on db.t4g.small, single-AZ, as the design matrix records. The
# single-AZ choice is deliberate and is the reason KSI-CNA-OFA is partially
# rather than fully satisfied: the compute tier is genuinely highly
# available and the data tier is not, so the honest claim is a measured
# restore time rather than a failover time.
#
# Three determinations lean on what is configured here:
#
#   KSI-SVC-VCM  -- IAM database authentication, password authentication
#                   disabled for the application users
#   KSI-SVC-SIN  -- customer-managed key at rest, rds.force_ssl in transit
#   KSI-RPL-ABO  -- automated backups with point-in-time recovery, retained
#                   for the window the objective register declares

locals {
  # KSI-RPL-ABO compares this against the recovery point objective declared
  # in the objective register. Seven days is what the register will carry;
  # when the register is built, the alignment check reads both rather than
  # trusting either.
  db_backup_retention_days = 7

  db_name          = "measurements"
  api_db_user      = "api_service"
  worker_db_user   = "worker_service"
  db_port          = 5432
  db_engine_family = "postgres17"
}

resource "aws_db_subnet_group" "main" {
  name       = "fedramp-20x-ksi"
  subnet_ids = aws_subnet.data[*].id

  description = "Data tier subnets. No internet route."
}

# KSI-CNA-DFP's build row 3: configurable feature sets declared explicitly
# rather than left at provider default. A default parameter group is
# functionality arriving by default, which is precisely what that indicator
# is written to catch.
resource "aws_db_parameter_group" "main" {
  name        = "fedramp-20x-ksi"
  family      = local.db_engine_family
  description = "Explicit parameters. TLS required, connections bounded, statements logged."

  # KSI-SVC-SIN's build row 2. Without this the server accepts unencrypted
  # connections and the client's sslmode is the only thing standing between
  # customer data and the wire.
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # KSI-CNA-ULN's session layer. AC-12 and SC-10 are session termination
  # and network disconnect, and the determination's reasoning is that a
  # connection which never terminates outlives the conditions that
  # authorised it. Ten minutes idle, one hour absolute.
  parameter {
    name  = "idle_in_transaction_session_timeout"
    value = "600000" # 10 minutes, milliseconds
  }

  parameter {
    name  = "idle_session_timeout"
    value = "3600000" # 1 hour, milliseconds
  }

  # Connection attempts, successful and failed, into the log. KSI-MLA-LET
  # names authentication events as a required category, and KSI-SVC-VCM's
  # build row 6 requires failed authentications be surfaced rather than
  # logged silently.
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  # DDL only, not every statement. Logging all statements on a database
  # holding customer data writes that data into the log, which moves the
  # exposure rather than reducing it.
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}

resource "aws_security_group" "database" {
  name        = "fedramp-20x-ksi-database"
  description = "Postgres. Inbound from the two service groups only."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-database"
  }
}

# Two separate rules rather than one rule naming both groups. The rules are
# the enumeration KSI-CNA-RNT asks for, and one rule per declared flow is
# what makes "every allowed flow is enumerated" literally true of the
# configuration rather than true after interpretation.
resource "aws_vpc_security_group_ingress_rule" "database_from_api" {
  security_group_id = aws_security_group.database.id
  description       = "Postgres from the api service"

  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_vpc_security_group_ingress_rule" "database_from_worker" {
  security_group_id = aws_security_group.database.id
  description       = "Postgres from the worker service"

  referenced_security_group_id = aws_security_group.worker.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

# No egress rule. The database initiates nothing.

resource "aws_db_instance" "main" {
  identifier = "fedramp-20x-ksi"

  engine = "postgres"

  # Major version pinned, minor left to the maintenance window below. A
  # full version pin would fight auto_minor_version_upgrade: AWS patches
  # the minor version and the next plan wants to roll it back, so the
  # declared state and the running state disagree by construction. Pinning
  # the major version declares what this project depends on and lets the
  # managed service do the patching KSI-SVC-EIS measures.
  engine_version = "17"
  instance_class = "db.t4g.small"

  db_name  = local.db_name
  username = "rds_master"

  # RDS generates the master password, stores it in Secrets Manager, and
  # rotates it. This project never sees it -- there is no
  # `random_password`, nothing in state, nothing in a variable. The
  # migration task reads it from Secrets Manager at run time and the
  # services never read it at all.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.secrets.arn

  allocated_storage     = 20
  max_allocated_storage = 50 # storage autoscaling, so a full disk is not an outage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.database.arn

  # KSI-SVC-VCM's build row 2. This is the switch that makes IAM auth
  # possible; the `rds_iam` grant in app/api/migrate.py is what makes it
  # mandatory for the application users.
  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.main.name

  multi_az = false # see the header comment, and KSI-CNA-OFA

  backup_retention_period = local.db_backup_retention_days
  backup_window           = "07:00-08:00" # UTC, outside a working day in most timezones
  maintenance_window      = "Sun:08:00-Sun:09:00"
  copy_tags_to_snapshot   = true

  # Point-in-time recovery to any second in the retention window, which is
  # what KSI-RPL-TRC's second test exercises -- recovery from compromise,
  # meaning restore to a moment before it, rather than only recovery from
  # failure.
  delete_automated_backups = false

  # The environment is destroyed between sessions and the snapshots are
  # deliberately kept, as the cost posture records. A final snapshot on
  # every destroy would accumulate one per session with no expiry, so this
  # skips it and relies on the automated backups, which do expire.
  skip_final_snapshot = true

  # Postgres logs into CloudWatch, where the connection and DDL events the
  # parameter group produces become queryable.
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Minor versions apply themselves in the maintenance window. KSI-SVC-EIS
  # measures improvement as rebuild cadence, and an engine that patches
  # itself is the managed-service half of that.
  auto_minor_version_upgrade = true

  # Deletion protection off, for the same reason skip_final_snapshot is
  # on: this environment is meant to be destroyed. A production deployment
  # would set both the other way.
  deletion_protection = false

  # Performance Insights is free at 7 days retention and is the only view
  # into what the database is actually doing.
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.database.arn

  tags = {
    Name      = "fedramp-20x-ksi"
    DataClass = "customer-data"
  }

  # The export's log groups must exist first, or RDS creates its own:
  # unencrypted, never expiring, and outside Terraform, so the teardown
  # leaves them behind. That is how /postgresql outlived the 2026-09-23
  # teardown with 544 KB of database logs in it (DECISIONS.md, 2026-10-01).
  depends_on = [aws_cloudwatch_log_group.rds]
}

# The database's exported logs, declared so they are encrypted with the logs
# key, expire, and go with the database at teardown. Found by
# svc-sin-cfg-aws-stores-use-declared-keys on its first run.
resource "aws_cloudwatch_log_group" "rds" {
  for_each = toset(["postgresql", "upgrade"])

  name              = "/aws/rds/instance/fedramp-20x-ksi/${each.key}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

# The /postgresql group left by the 2026-09-23 teardown, adopted at the next
# full apply rather than deleted now: its contents are database logs from
# the phase 2 sessions, and whether to keep them is the record's call, not
# a cleanup's. Ignored by the drift plan, which targets persistent files.
import {
  to = aws_cloudwatch_log_group.rds["postgresql"]
  id = "/aws/rds/instance/fedramp-20x-ksi/postgresql"
}
