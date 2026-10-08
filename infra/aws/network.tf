# The network the application runs in.
#
# The shape of this file is the architecture's strongest single security
# claim, so it is worth stating plainly: private subnets have no route to
# the internet at all. Not a filtered route, not a NAT gateway with rules --
# no route. Traffic to AWS services leaves through VPC endpoints, and
# traffic to anywhere else has nowhere to go.
#
# KSI-CNA-RNT's design rationale turns on this. "Outbound is absent rather
# than filtered" is a different and stronger claim than "outbound is
# restricted", and it is falsifiable: the validation evidence is a
# deliberate test that opens a connection to an internet address from a
# running task and confirms it fails.
#
# It is bought rather than free. Six interface endpoints at roughly 7 USD
# each costs more than the NAT gateway they replace, at about 32. The design
# matrix records that as a deliberate purchase.
#
# Three tiers, each with its own route table, per KSI-CNA-ULN's subnet
# tiering row:
#
#   public  -- the load balancer, and nothing else
#   app     -- ECS tasks
#   data    -- RDS, and the interface endpoints
#
# Distinct route tables matter for more than tidiness. ULN's test is
# whether flows would still be constrained if every security group were
# wiped, and that question only has a good answer if the topology itself
# constrains them.

locals {
  vpc_cidr = "10.20.0.0/16"

  # Two availability zones. The load balancer requires two, and the compute
  # tier is genuinely multi-AZ. The data tier is single-AZ by design (see
  # database.tf) but still needs a subnet in each AZ for the subnet group.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  public_subnets = ["10.20.0.0/24", "10.20.1.0/24"]
  app_subnets    = ["10.20.10.0/24", "10.20.11.0/24"]
  data_subnets   = ["10.20.20.0/24", "10.20.21.0/24"]

  # The AWS services tasks are permitted to reach. Each becomes an
  # interface endpoint with a restrictive policy below. This list is the
  # whole of the environment's outbound reach -- there is no other path.
  interface_endpoints = {
    ecr_api        = "ecr.api"
    ecr_dkr        = "ecr.dkr"
    logs           = "logs"
    secretsmanager = "secretsmanager"
    kms            = "kms"
    sts            = "sts"
  }
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_region" "current" {}

resource "aws_vpc" "main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # interface endpoints resolve by private DNS

  tags = {
    Name = "fedramp-20x-ksi"
  }
}

# The VPC's default security group, which AWS creates with the VPC and
# will not delete. Undeclared, its rules are AWS's defaults -- all traffic
# between its members, all egress -- rather than code, and anything
# launched without a group lands in it.
#
# Declared with no rules at all, so it admits and emits nothing and is
# useless as a fallback. Every workload here names its own group. This is
# the CIS benchmark's position and Security Hub's EC2.2 control, both of
# which now run continuously. It is also what lets the collector's
# live_is_declared check pass while the environment stands: this group
# was deliberately not excused there (DECISIONS.md, 2026-09-23).
#
# Terraform does not create this resource; it adopts the existing group
# and removes its rules. On destroy it is only dropped from state, and
# the group goes when the VPC does.
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-default-deny"
  }
}

# --- Public tier: the load balancer only ---

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi"
  }
}

resource "aws_subnet" "public" {
  count = length(local.public_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_subnets[count.index]
  availability_zone = local.azs[count.index]

  # Off deliberately. Nothing in a public subnet should ever receive a
  # public IP by default; the load balancer gets its addresses from the
  # service, not from the subnet.
  map_public_ip_on_launch = false

  tags = {
    Name = "fedramp-20x-ksi-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-public"
    Tier = "public"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- App tier: ECS tasks ---

resource "aws_subnet" "app" {
  count = length(local.app_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.app_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "fedramp-20x-ksi-app-${local.azs[count.index]}"
    Tier = "app"
  }
}

# No routes are declared on this table beyond the local route AWS creates
# implicitly, and the S3 gateway endpoint association below. That absence
# is the control. A `aws_route` resource pointing anywhere else appearing
# here is the significant finding KSI-CNA-RNT's remediation section
# describes -- it silently converts the absent-egress claim into a
# filtered-egress claim.
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-app"
    Tier = "app"
  }
}

resource "aws_route_table_association" "app" {
  count = length(aws_subnet.app)

  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app.id
}

# --- Data tier: RDS and the interface endpoints ---

resource "aws_subnet" "data" {
  count = length(local.data_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.data_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "fedramp-20x-ksi-data-${local.azs[count.index]}"
    Tier = "data"
  }
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-data"
    Tier = "data"
  }
}

resource "aws_route_table_association" "data" {
  count = length(aws_subnet.data)

  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# --- Egress: endpoints, and nothing else ---

# The S3 gateway endpoint is free and is a route table entry rather than an
# ENI, which is why it can be attached to both private tiers without cost.
# ECR image layers live in S3, so image pulls do not work without it.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.app.id,
    aws_route_table.data.id,
  ]

  policy = data.aws_iam_policy_document.s3_endpoint.json

  tags = {
    Name = "fedramp-20x-ksi-s3"
  }
}

# KSI-CNA-ULN's build row 3: principal and action restrictions on every
# endpoint, "so the endpoint layer is a boundary rather than a tunnel". An
# endpoint with the default allow-everything policy is a hole in the
# perimeter that happens to point at AWS.
data "aws_iam_policy_document" "s3_endpoint" {
  # ECR stores image layers in S3 buckets it owns, so a pull needs read
  # access to them. Scoped to the layer bucket for this region rather than
  # to all of S3.
  statement {
    sid    = "AllowECRLayerPull"
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::prod-${data.aws_region.current.name}-starport-layer-bucket/*",
    ]
  }

  # The buckets this project owns and the tasks legitimately use: the
  # extract landing prefix the worker writes to, and the log store.
  #
  # Principal "*" with an aws:PrincipalArn condition, because a gateway
  # endpoint does not honour named principals: "With gateway endpoints, the
  # Principal element must be set to *. To specify a principal, use the
  # aws:PrincipalArn condition key" (AWS PrivateLink docs). Until 2026-10-02
  # this statement named the two roles as principals and so allowed nothing;
  # no extract had ever landed, which the first phase 2 to try found
  # (DECISIONS.md, 2026-10-02). Same two roles, in the form that works.
  statement {
    sid    = "AllowProjectBuckets"
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values = [
        aws_iam_role.api_task.arn,
        aws_iam_role.worker_task.arn,
      ]
    }

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.extracts.arn,
      "${aws_s3_bucket.extracts.arn}/*",
    ]
  }
}

# One security group for all six interface endpoints. They are the same
# thing from the network's point of view -- an HTTPS listener reachable
# from the app tier -- and splitting them would multiply rules without
# changing what is reachable.
resource "aws_security_group" "endpoints" {
  name        = "fedramp-20x-ksi-endpoints"
  description = "Interface endpoints. HTTPS from the app tier only."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "fedramp-20x-ksi-endpoints"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_api" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from the api service"

  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_worker" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from the worker service"

  referenced_security_group_id = aws_security_group.worker.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# Endpoints need no egress of their own; they answer on the connection
# they received. No egress rule is declared, which means none is permitted
# -- KSI-CNA-RNT reads default-allow-all outbound as a failure, so the
# absence here is deliberate rather than an oversight.

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type = "Interface"

  subnet_ids         = aws_subnet.data[*].id
  security_group_ids = [aws_security_group.endpoints.id]

  # Without this, calls to the service's public hostname would resolve to
  # the public endpoint and then fail, since there is no route there. With
  # it, the hostname resolves to the endpoint's private address and the
  # SDKs need no configuration at all.
  private_dns_enabled = true

  policy = data.aws_iam_policy_document.interface_endpoint[each.key].json

  tags = {
    Name = "fedramp-20x-ksi-${each.key}"
  }
}

# Per-endpoint policies. Each names the principals permitted to use it and
# the actions they may take -- the same enumeration discipline KSI-CNA-DFP
# applies to task definitions and IAM policies, applied to the network
# boundary.
data "aws_iam_policy_document" "interface_endpoint" {
  for_each = local.interface_endpoints

  statement {
    sid    = "AllowDeclaredPrincipals"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.api_task.arn,
        aws_iam_role.worker_task.arn,
        aws_iam_role.task_execution.arn,
        # The migration task reads the database master secret through the
        # secretsmanager endpoint and decrypts it through the kms one.
        # Omitting it here would leave a task whose IAM policy and security
        # group both permit the call, failing on the endpoint policy --
        # the kind of three-places-must-agree failure this architecture
        # makes possible and which is invisible until the task runs.
        aws_iam_role.migrate_task.arn,
      ]
    }

    actions   = local.endpoint_actions[each.key]
    resources = ["*"]
  }
}

# What each endpoint is for, stated as the actions permitted through it.
# "*" appears nowhere.
locals {
  endpoint_actions = {
    # Image pulls. The execution role authenticates and fetches layers;
    # neither task role has any use for these.
    ecr_api = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    ecr_dkr = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]

    # Container logs out. No read actions: a task that can read the log
    # group can read its own history, which is the first thing an
    # attacker would use to find what else exists.
    logs = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    # The api reads the task TLS certificate; the migration task reads the
    # database master secret. Nothing writes.
    secretsmanager = [
      "secretsmanager:GetSecretValue",
    ]

    # Decrypt only, for the secrets and the S3 objects. No key
    # administration through the endpoint, ever.
    kms = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]

    # Both tasks assume their role through the task metadata endpoint
    # rather than STS directly, but the SDKs call GetCallerIdentity for
    # region and identity resolution and RDS IAM auth is signed against
    # it.
    sts = [
      "sts:GetCallerIdentity",
    ]
  }
}

# --- Flow logs ---
#
# The evidence source for most of KSI-CNA-RNT's and KSI-CNA-ULN's
# validation rows: zero accepted flows outside a declared allow, zero
# outbound connections to internet destinations, rejected flows logged
# rather than silently dropped.
#
# ACCEPT and REJECT both, deliberately. Rejected flows are the more
# interesting half -- they are attempts -- and KSI-CNA-RNT's validation
# names them specifically.
#
# These go to CloudWatch Logs rather than into the object-locked corpus in
# log_corpus.tf. That is a platform constraint rather than a choice: VPC
# flow log delivery to S3 fails when the destination bucket carries a
# default Object Lock retention period, which the log store does. Recorded
# in docs/DECISIONS.md.
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/fedramp-20x-ksi/vpc/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "fedramp-20x-ksi-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

# An inline policy rather than a managed one. KSI-CNA-DFP bars AWS-managed
# policies on workload identities on the grounds that their contents change
# outside our control, and the same reasoning applies to service roles.
resource "aws_iam_role_policy" "flow_logs" {
  name   = "flow-log-delivery"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  # The default format omits the fields the determinations actually need:
  # pkt-srcaddr and pkt-dstaddr survive NAT and endpoint rewriting, and
  # flow-direction is what makes "outbound to an internet destination"
  # expressible as a query rather than an inference.
  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}",
    "$${srcaddr}", "$${dstaddr}", "$${srcport}", "$${dstport}",
    "$${protocol}", "$${packets}", "$${bytes}",
    "$${start}", "$${end}", "$${action}", "$${log-status}",
    "$${vpc-id}", "$${subnet-id}", "$${instance-id}", "$${tcp-flags}",
    "$${type}", "$${pkt-srcaddr}", "$${pkt-dstaddr}",
    "$${region}", "$${az-id}", "$${flow-direction}", "$${traffic-path}",
  ])

  max_aggregation_interval = 60

  tags = {
    Name = "fedramp-20x-ksi"
  }

  # Delivery starts as soon as the flow log exists; until the role's policy
  # is attached it is denied CreateLogStream, and the first records are lost.
  # Seen in sessions 1 and 2 (iam-elp-ops-aws-project-roles-not-denied,
  # 2026-10-07): the policy was created after the flow log.
  depends_on = [aws_iam_role_policy.flow_logs]
}
