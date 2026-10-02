# The two services, and the identities and network positions that contain
# them.
#
# This file carries more of the assessment's weight than any other. Three
# determinations are built here almost in full:
#
#   KSI-CNA-MAT -- per-service segmentation, per-service task roles,
#                  container hardening. The determination's point is that
#                  lateral movement is a graph question combining network
#                  reachability and identity permission, and that neither
#                  alone is sufficient: a task with a narrow security group
#                  and a broad role has poor containment despite looking
#                  fine on the network.
#
#   KSI-CNA-DFP -- command, entrypoint, ports, capabilities and user stated
#                  explicitly rather than inherited from the image, and no
#                  AWS-managed policy on any workload identity.
#
#   KSI-IAM-ELP -- each role scoped to the operations its service actually
#                  performs, with the declaration itself in code so
#                  conformance is checkable.
#
# The two services cannot reach each other. No security group rule permits
# it in either direction, which is what the KSI-CNA-MAT deliberate test
# confirms by attempting the connection and failing.

# Images are pinned by digest, not tag, so the services cannot be created
# until images exist in ECR. That is a real ordering constraint rather than
# an inconvenience: KSI-SVC-VRI's build row 2 requires task definitions
# reference images by digest, and a digest cannot be looked up for an image
# that has not been built.
#
# So this root applies in two phases:
#
#   1. deploy_services = false  -- network, database, registry, identities
#   2. build and push images, then deploy_services = true
#
# The alternative would be a tag reference that resolves to whatever is
# there at apply time, which is the mutable pointer VRI exists to reject.
variable "deploy_services" {
  description = "Create the ECS services. Requires images already pushed to ECR; see infra/README.md."
  type        = bool
  default     = false
}

variable "app_image_tag" {
  description = "Image tag to resolve to a digest. Immutable tags mean this always names one specific build."
  type        = string
  default     = "v1"
}

data "aws_ecr_image" "service" {
  for_each = var.deploy_services ? local.services : toset([])

  repository_name = aws_ecr_repository.service[each.key].name
  image_tag       = var.app_image_tag
}

locals {
  deploy_count = var.deploy_services ? 1 : 0

  api_port = 8443

  # Referenced by digest. The tag above is only how the digest is found.
  service_images = var.deploy_services ? {
    for name in local.services :
    name => "${aws_ecr_repository.service[name].repository_url}@${data.aws_ecr_image.service[name].image_digest}"
  } : {}
}

# --- Security groups: one per service ---
#
# KSI-CNA-MAT's build row 1. Without this, compromising either service
# would yield the network position of both, and the per-service
# segmentation claim would be an assertion rather than a property.

resource "aws_security_group" "api" {
  name        = "fedramp-20x-ksi-api"
  description = "api service. Inbound from the load balancer only."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name    = "fedramp-20x-ksi-api"
    Service = "api"
  }
}

resource "aws_security_group" "worker" {
  name        = "fedramp-20x-ksi-worker"
  description = "worker service. No inbound from anywhere."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name    = "fedramp-20x-ksi-worker"
    Service = "worker"
  }
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  security_group_id = aws_security_group.api.id
  description       = "HTTPS from the load balancer"

  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.api_port
  to_port                      = local.api_port
}

# The worker has no ingress rule at all. Not a narrow one -- none. It has
# no listener, so any rule would permit a flow that does not exist, and
# KSI-CNA-MAT bounds minimal as "no port open that no declared flow uses".

# Egress, enumerated per destination. KSI-CNA-RNT reads a default
# allow-all egress rule as a failure regardless of what else is in place,
# so every rule below names a specific destination group and port.

resource "aws_vpc_security_group_egress_rule" "api_to_database" {
  security_group_id = aws_security_group.api.id
  description       = "Postgres to the database"

  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_vpc_security_group_egress_rule" "api_to_endpoints" {
  security_group_id = aws_security_group.api.id
  description       = "HTTPS to the interface endpoints"

  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# S3 is a gateway endpoint, which is a route rather than an ENI, so it has
# no security group to reference. A prefix list is the only way to name it
# as a destination, and it is still a named destination rather than
# 0.0.0.0/0.
resource "aws_vpc_security_group_egress_rule" "api_to_s3" {
  security_group_id = aws_security_group.api.id
  description       = "HTTPS to S3 through the gateway endpoint"

  prefix_list_id = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol    = "tcp"
  from_port      = 443
  to_port        = 443
}

resource "aws_vpc_security_group_egress_rule" "worker_to_database" {
  security_group_id = aws_security_group.worker.id
  description       = "Postgres to the database"

  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_vpc_security_group_egress_rule" "worker_to_endpoints" {
  security_group_id = aws_security_group.worker.id
  description       = "HTTPS to the interface endpoints"

  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "worker_to_s3" {
  security_group_id = aws_security_group.worker.id
  description       = "HTTPS to S3 through the gateway endpoint"

  prefix_list_id = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol    = "tcp"
  from_port      = 443
  to_port        = 443
}

# --- Identities ---
#
# One execution role, shared: it does the same thing for both services
# (pull the image, write to the log group) and holds no application
# permission at all.
#
# Two task roles, separate: these are what the application code runs as,
# and KSI-CNA-MAT's build row 2 bars a shared execution-plus-task role for
# exactly this reason.

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # Without this, any ECS task in any account could assume the role if
    # its ARN leaked. The condition binds the trust to this account's
    # tasks.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "fedramp-20x-ksi-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json

  # KSI-CNA-ULN's build row 5, the session layer: bounded token lifetimes
  # on every role. One hour is the AWS minimum.
  max_session_duration = 3600
}

# AmazonECSTaskExecutionRolePolicy would be one line here and is
# deliberately not used. KSI-CNA-DFP's build row 2 bars AWS-managed
# policies on workload identities on the grounds that their contents change
# outside our control -- a managed policy is a privilege grant AWS can
# widen without us noticing.
data "aws_iam_policy_document" "task_execution" {
  statement {
    sid    = "PullImages"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]

    resources = ["*"] # GetAuthorizationToken takes no resource
  }

  statement {
    sid    = "DecryptImageLayers"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.artifacts.arn]
  }

  statement {
    sid    = "WriteContainerLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "${aws_cloudwatch_log_group.api.arn}:*",
      "${aws_cloudwatch_log_group.worker.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "task_execution" {
  name   = "execution"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.task_execution.json
}

# --- api task role ---

resource "aws_iam_role" "api_task" {
  name                 = "fedramp-20x-ksi-api-task"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
  max_session_duration = 3600

  tags = {
    Service = "api"
  }
}

data "aws_iam_policy_document" "api_task" {
  # The database, as itself and nobody else. The resource ARN names the
  # specific database user: this role cannot mint a token for the worker's
  # user, or for the master user.
  statement {
    sid    = "ConnectAsApiUser"
    effect = "Allow"

    actions   = ["rds-db:connect"]
    resources = ["arn:aws:rds-db:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/${local.api_db_user}"]
  }

  statement {
    sid    = "ReadTaskCertificate"
    effect = "Allow"

    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.task_tls.arn]
  }

  statement {
    sid    = "DecryptTaskCertificate"
    effect = "Allow"

    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "api_task" {
  name   = "api"
  role   = aws_iam_role.api_task.id
  policy = data.aws_iam_policy_document.api_task.json
}

# --- worker task role ---

resource "aws_iam_role" "worker_task" {
  name                 = "fedramp-20x-ksi-worker-task"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
  max_session_duration = 3600

  tags = {
    Service = "worker"
  }
}

data "aws_iam_policy_document" "worker_task" {
  statement {
    sid    = "ConnectAsWorkerUser"
    effect = "Allow"

    actions   = ["rds-db:connect"]
    resources = ["arn:aws:rds-db:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/${local.worker_db_user}"]
  }

  # Write only, and only under the extract prefix. No GetObject: the
  # worker produces extracts and never reads them back, so read access
  # would be a permission with no declared operation behind it -- the
  # thing KSI-CNA-MAT's blast radius computation is built to surface.
  statement {
    sid    = "LandExtracts"
    effect = "Allow"

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.extracts.arn}/measurements/*"]
  }

  # The network-boundary dimension KSI-CNA-RNT adds for resources with no
  # interface: whether access is restricted to the VPC or reachable from
  # anywhere with the right credential. Writes must arrive through the S3
  # gateway endpoint.
  #
  # This was a statement in the extract bucket's policy until 2026-09-23.
  # It names this role and the endpoint, both ephemeral, and the bucket
  # policy it shared needed to persist -- so it moved here, next to the
  # things it names. The effect is the same: an explicit deny wins whether
  # it sits on the identity or the resource. What differs is who can remove
  # it, since whoever can edit this role's policy can now drop the
  # restriction without touching the bucket. Every such edit is a
  # non-pipeline IAM mutation, which KSI-SVC-ACM's mutation query watches.
  statement {
    sid    = "WritesOnlyThroughEndpoint"
    effect = "Deny"

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.extracts.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.s3.id]
    }
  }

  statement {
    sid    = "EncryptExtracts"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.artifacts.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "worker_task" {
  name   = "worker"
  role   = aws_iam_role.worker_task.id
  policy = data.aws_iam_policy_document.worker_task.json
}

# --- migration task role ---
#
# The only identity permitted to read the database master password. It
# exists separately from both service roles because the migration needs
# privileges the services must not hold: if the api's role could read the
# master secret, then compromising the api would yield the database
# outright and every grant in app/api/migrate.py would be decorative.

resource "aws_iam_role" "migrate_task" {
  name                 = "fedramp-20x-ksi-migrate-task"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
  max_session_duration = 3600

  tags = {
    Service = "migrate"
  }
}

data "aws_iam_policy_document" "migrate_task" {
  statement {
    sid    = "ReadMasterSecret"
    effect = "Allow"

    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.main.master_user_secret[0].secret_arn]
  }

  statement {
    sid    = "DecryptMasterSecret"
    effect = "Allow"

    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "migrate_task" {
  name   = "migrate"
  role   = aws_iam_role.migrate_task.id
  policy = data.aws_iam_policy_document.migrate_task.json
}

# --- Log groups ---

resource "aws_cloudwatch_log_group" "api" {
  name              = "/fedramp-20x-ksi/ecs/api"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Service = "api"
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/fedramp-20x-ksi/ecs/worker"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Service = "worker"
  }
}

# --- Cluster ---

resource "aws_ecs_cluster" "main" {
  name = "fedramp-20x-ksi"

  # KSI-CNA-DFP's build row 3: configurable feature sets declared rather
  # than left at default. Container Insights is the observability feature
  # here, and off is a decision -- it bills per metric and this
  # environment's operational health is already covered by the alarms in
  # health.tf.
  setting {
    name  = "containerInsights"
    value = "disabled"
  }

  configuration {
    execute_command_configuration {
      # This field does NOT disable ECS Exec -- it only selects where exec
      # session I/O is recorded. Exec availability is controlled by
      # enable_execute_command on the service, which is absent below and
      # therefore false.
      #
      # So the posture is: Exec is off by omission, and if anyone turns it
      # on with ecs:UpdateService they get an interactive shell in the api
      # task. DEFAULT rather than NONE means that session is at least
      # recorded to the task's configured log destination. NONE would mean
      # a shell in the application tier leaving no trace, which is the
      # opposite of what KSI-MLA-LET asks of this surface.
      logging = "DEFAULT"
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  # Fargate only. No EC2 capacity provider means no instances to patch,
  # which is what lets KSI-SVC-EIS measure improvement as rebuild cadence
  # rather than patch latency.
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# --- Task definitions ---
#
# Every field KSI-CNA-DFP names is stated here even where it matches the
# image's own declaration. The duplication is the point: the verification
# row is "running container configuration matches the declared task
# definition", which is only a meaningful check if the declaration exists
# in both places and could disagree.

locals {
  # Common container hardening, applied to every container definition.
  # KSI-CNA-MAT's build row 3 calls this the cheapest surface reduction
  # available and the container-level analogue of network segmentation.
  hardening = {
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001:10001"
    linuxParameters = {
      capabilities = {
        # Everything dropped, nothing added. Enumerated rather than
        # minimised, per DFP.
        drop = ["ALL"]
        add  = []
      }
      initProcessEnabled = true # reaps zombies; PID 1 is python, not an init
    }
    # ECS stores these defaults whether or not they are sent. Stated here so
    # the declaration matches what is live: left out, every plan with the
    # services up showed the task definitions as needing replacement, which
    # would make the drift check report drift that is not there
    # (DECISIONS.md, 2026-10-02).
    systemControls = []
    volumesFrom    = []
  }
}

resource "aws_ecs_task_definition" "api" {
  count = local.deploy_count

  family                   = "fedramp-20x-ksi-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.task_execution.arn
  task_role_arn      = aws_iam_role.api_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64" # matches the image built for aarch64, and costs less
    operating_system_family = "LINUX"
  }

  # The writable mount the read-only root filesystem makes necessary. The
  # TLS material is written here and nowhere else.
  #
  # Scratch space, and NOT where the task certificate goes.
  #
  # Fargate mounts this volume owned by root with mode 0755, and the
  # containers run as uid 10001, so nothing in this task can actually write
  # to it. That is measured, not assumed -- it is what crashed every api
  # task on 2026-09-23 with `Permission denied: '/tmp/tls'`.
  #
  # The certificate now materialises in /dev/shm, a separate tmpfs mount
  # that `readonlyRootFilesystem` does not cover and that is world-writable.
  # That is strictly better: /dev/shm is memory, so the private key never
  # touches disk, where this volume's ephemeral storage would have.
  #
  # The mount is kept because a read-only root filesystem needs somewhere
  # for anything that expects /tmp to exist, and because removing it would
  # make the task definition disagree with the hardening block every other
  # service shares. It is deliberately not described as writable.
  #
  # Not tmpfs: Fargate does not support linuxParameters.tmpfs, so this is
  # a Docker volume on the task's ephemeral storage.
  volume {
    name = "tmp"

    configure_at_launch = false
  }

  container_definitions = jsonencode([
    merge(local.hardening, {
      name  = "api"
      image = local.service_images["api"]

      # Stated rather than inherited from the image, per KSI-CNA-DFP's
      # build row 1.
      entryPoint = ["python"]
      command    = ["main.py"]

      essential = true

      portMappings = [{
        containerPort = local.api_port
        # awsvpc requires the two to match, and ECS records it either way.
        hostPort = local.api_port
        protocol = "tcp"
      }]

      mountPoints = [{
        sourceVolume  = "tmp"
        containerPath = "/tmp"
        readOnly      = false
      }]

      # Secret ARNs, not secret values. KSI-SVC-ASM's build row 1 bars
      # secrets in environment variables; a pointer to one is not the
      # secret, and the application fetches the material itself at
      # startup with its own role.
      environment = [
        { name = "AWS_REGION", value = data.aws_region.current.name },
        { name = "PORT", value = tostring(local.api_port) },
        { name = "TLS_SECRET_ARN", value = aws_secretsmanager_secret.task_tls.arn },
        { name = "DB_HOST", value = aws_db_instance.main.address },
        { name = "DB_PORT", value = tostring(local.db_port) },
        { name = "DB_NAME", value = local.db_name },
        { name = "DB_USER", value = local.api_db_user },
        { name = "LOG_LEVEL", value = "INFO" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "api"
        }
      }
    })
  ])

  tags = {
    Service = "api"
  }
}

resource "aws_ecs_task_definition" "worker" {
  count = local.deploy_count

  family                   = "fedramp-20x-ksi-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.task_execution.arn
  task_role_arn      = aws_iam_role.worker_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  volume {
    name                = "tmp"
    configure_at_launch = false
  }

  container_definitions = jsonencode([
    merge(local.hardening, {
      name  = "worker"
      image = local.service_images["worker"]

      entryPoint = ["python"]
      command    = ["main.py"]

      essential = true

      # No portMappings. The worker listens on nothing.

      mountPoints = [{
        sourceVolume  = "tmp"
        containerPath = "/tmp"
        readOnly      = false
      }]

      environment = [
        { name = "AWS_REGION", value = data.aws_region.current.name },
        { name = "DB_HOST", value = aws_db_instance.main.address },
        { name = "DB_PORT", value = tostring(local.db_port) },
        { name = "DB_NAME", value = local.db_name },
        { name = "DB_USER", value = local.worker_db_user },
        { name = "EXTRACT_BUCKET", value = aws_s3_bucket.extracts.bucket },
        { name = "EXTRACT_PREFIX", value = "measurements" },
        { name = "EXTRACT_KMS_KEY_ARN", value = aws_kms_key.artifacts.arn },
        { name = "EXTRACT_INTERVAL_SECONDS", value = "900" },
        { name = "EXTRACT_WINDOW_MINUTES", value = "20" },
        { name = "LOG_LEVEL", value = "INFO" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "worker"
        }
      }
    })
  ])

  tags = {
    Service = "worker"
  }
}

# The migration, as a task definition that is never run as a service.
# Applied by `aws ecs run-task` once, after the first deploy; see
# infra/README.md.
resource "aws_ecs_task_definition" "migrate" {
  count = local.deploy_count

  family                   = "fedramp-20x-ksi-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.task_execution.arn
  task_role_arn      = aws_iam_role.migrate_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([
    merge(local.hardening, {
      name  = "migrate"
      image = local.service_images["api"] # same image, different entry point

      entryPoint = ["python"]
      command    = ["migrate.py"]

      essential = true

      environment = [
        { name = "AWS_REGION", value = data.aws_region.current.name },
        { name = "DB_HOST", value = aws_db_instance.main.address },
        { name = "DB_PORT", value = tostring(local.db_port) },
        { name = "DB_NAME", value = local.db_name },
        { name = "API_DB_USER", value = local.api_db_user },
        { name = "WORKER_DB_USER", value = local.worker_db_user },
        { name = "MASTER_SECRET_ARN", value = aws_db_instance.main.master_user_secret[0].secret_arn },
        { name = "LOG_LEVEL", value = "INFO" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "migrate"
        }
      }
    })
  ])

  tags = {
    Service = "migrate"
  }
}

# The migration runs as the api service's security group, since it needs
# the same reach: the database, and the endpoints. It is a separate role
# but the same network position.
resource "aws_security_group" "migrate" {
  name        = "fedramp-20x-ksi-migrate"
  description = "One-off migration task. Database and endpoints only."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name    = "fedramp-20x-ksi-migrate"
    Service = "migrate"
  }
}

resource "aws_vpc_security_group_egress_rule" "migrate_to_database" {
  security_group_id = aws_security_group.migrate.id
  description       = "Postgres to the database"

  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_vpc_security_group_egress_rule" "migrate_to_endpoints" {
  security_group_id = aws_security_group.migrate.id
  description       = "HTTPS to the interface endpoints"

  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "migrate_to_s3" {
  security_group_id = aws_security_group.migrate.id
  description       = "HTTPS to S3 through the gateway endpoint"

  prefix_list_id = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol    = "tcp"
  from_port      = 443
  to_port        = 443
}

resource "aws_vpc_security_group_ingress_rule" "database_from_migrate" {
  security_group_id = aws_security_group.database.id
  description       = "Postgres from the one-off migration task"

  referenced_security_group_id = aws_security_group.migrate.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_migrate" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from the one-off migration task"

  referenced_security_group_id = aws_security_group.migrate.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# --- Services ---

resource "aws_ecs_service" "api" {
  count = local.deploy_count

  name            = "api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api[0].arn
  launch_type     = "FARGATE"

  # Two tasks across two availability zones. KSI-CNA-OFA's position is that
  # the compute tier is genuinely highly available even though the data
  # tier is not, and one task is not.
  desired_count = 2

  network_configuration {
    subnets          = aws_subnet.app[*].id
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false # there is no route anyway; stated regardless
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = local.api_port
  }

  # Suppress health checks for the first 60 seconds of a task's life, so
  # a task is not killed for failing a check while it is still fetching
  # its certificate and binding. This is startup tolerance, not the
  # rollback mechanism -- deployment_circuit_breaker below is what rolls a
  # bad deployment back.
  health_check_grace_period_seconds = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # KSI-CNA-OFA: desired-count maintenance and task replacement are the
  # strongest automatic enforcement in the architecture, and a platform
  # guarantee rather than project code.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  # desired_count only. The task definition is deliberately NOT ignored:
  # this flow pins images by digest, so Terraform is the thing that should
  # decide which revision runs, and an apply correcting a drifted revision
  # is the behaviour KSI-SVC-ACM wants. What is ignored is the count, which
  # a scaling action may legitimately have changed.
  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = {
    Service = "api"
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_ecs_service" "worker" {
  count = local.deploy_count

  name            = "worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker[0].arn
  launch_type     = "FARGATE"

  # One. Two instances would multiply the duplicate landings described in
  # app/worker/main.py -- they do not cause them. The overlapping window
  # means the landing is at-least-once even with a single instance, and
  # the analytics side deduplicates on the record id.
  desired_count = 1

  network_configuration {
    subnets          = aws_subnet.app[*].id
    security_groups  = [aws_security_group.worker.id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # A single-task service cannot hold 100% healthy through a replacement.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = {
    Service = "worker"
  }
}
