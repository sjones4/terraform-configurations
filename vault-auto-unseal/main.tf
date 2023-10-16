# ---------------------------------------------------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------------------------------------------------

terraform {
  required_version = ">= 0.12.26"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "< 4.0"
    }
  }
}

provider "aws" {
  region = "${var.region}"

  # Define these as environment variables or below; AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  # access_key = ""
  # secret_key = ""

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true

  endpoints {
    iam = "https://iam${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
    sts = "https://sts${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
    kms = "https://kms${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
    ec2 = "https://ec2${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
    elb = "https://elb${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
    autoscaling = "https://autoscaling${var.endpoint_name_suffix}.${var.region}.${var.endpoint_url_suffix}"
  }

  default_tags {
    tags = {
      owner = "vault-terraform-cluster"
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_vpc" "vpc" {
  default = length(var.vpc_tags) == 0 ? true : false
  tags    = var.vpc_tags
}

data "aws_subnet_ids" "subnet" {
  vpc_id = data.aws_vpc.vpc.id
  tags   = var.subnet_tags
}

data "aws_iam_policy_document" "instance_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------------------------------------------------

data "template_file" "user_data_vault_cluster" {
  template = file("user-data-vault.sh")

  vars = {
    aws_region               = var.region
    aws_endpoint_name_suffix = var.endpoint_name_suffix
    aws_endpoint_url_suffix  = var.endpoint_url_suffix
    vault_unseal_key_arn     = data.aws_kms_alias.vault_unseal_key.target_key_arn
    consul_cluster_tag_key   = var.consul_cluster_tag_key
    consul_cluster_tag_value = var.consul_cluster_name
  }
}

data "aws_kms_alias" "vault_unseal_key" {
  name = "alias/${var.auto_unseal_kms_key_alias}"
}

resource "aws_autoscaling_group" "vault_autoscaling_group" {
  name_prefix = "${var.vault_cluster_name}-"

  launch_template {
    id      = aws_launch_template.vault_launch_template.id
    version = "$Latest"
  }

  vpc_zone_identifier = data.aws_subnet_ids.subnet.ids

  # Use a fixed-size cluster
  min_size             = var.vault_cluster_size
  max_size             = var.vault_cluster_size
  desired_capacity     = var.vault_cluster_size

  health_check_type         = "EC2"
  health_check_grace_period = 300
  wait_for_capacity_timeout = "5m"

  tag {
    key                 = "Name"
    value               = "${var.vault_cluster_name}"
    propagate_at_launch = true
  }

  tag {
    key                 = "using_auto_unseal"
    value               = "1"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [load_balancers, target_group_arns]
  }

  depends_on = [
    aws_security_group_rule.vault_allow_ssh_inbound_from_cidr_blocks,
    aws_security_group_rule.vault_allow_api_inbound_from_cidr_blocks,
    aws_security_group_rule.vault_allow_cluster_inbound_from_self,
    aws_security_group_rule.vault_allow_cluster_inbound_from_self_api,
    aws_security_group_rule.vault_allow_all_outbound
  ]
}

resource "aws_launch_template" "vault_launch_template" {
  name_prefix   = "${var.vault_cluster_name}-"
  image_id      = var.ami_id
  instance_type = var.vault_instance_type
  user_data     = base64encode(data.template_file.user_data_vault_cluster.rendered)

  iam_instance_profile {
    name = aws_iam_instance_profile.vault_instance_profile.name
  }
  key_name = var.ssh_key_name

  network_interfaces {
    associate_public_ip_address = var.associate_public_ips
    delete_on_termination = true
    security_groups = [aws_security_group.vault_launch_template_security_group.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      delete_on_termination = true
      volume_size = 10
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "vault_launch_template_security_group" {
  name_prefix = "${var.vault_cluster_name}-"
  description = "Security group for the ${var.vault_cluster_name} launch template"
  vpc_id      = data.aws_vpc.vpc.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    "Name" = var.vault_cluster_name
  }
}

resource "aws_security_group_rule" "vault_allow_ssh_inbound_from_cidr_blocks" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [data.aws_vpc.vpc.cidr_block]

  security_group_id = aws_security_group.vault_launch_template_security_group.id
}

resource "aws_security_group_rule" "vault_allow_api_inbound_from_cidr_blocks" {
  type        = "ingress"
  from_port   = var.vault_api_port
  to_port     = var.vault_api_port
  protocol    = "tcp"
  cidr_blocks = [data.aws_vpc.vpc.cidr_block]

  security_group_id = aws_security_group.vault_launch_template_security_group.id
}

resource "aws_security_group_rule" "vault_allow_cluster_inbound_from_self" {
  type      = "ingress"
  from_port = var.vault_cluster_port
  to_port   = var.vault_cluster_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.vault_launch_template_security_group.id
}

resource "aws_security_group_rule" "vault_allow_cluster_inbound_from_self_api" {
  type      = "ingress"
  from_port = var.vault_api_port
  to_port   = var.vault_api_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.vault_launch_template_security_group.id
}

resource "aws_security_group_rule" "vault_allow_all_outbound" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.vault_launch_template_security_group.id
}

resource "aws_iam_instance_profile" "vault_instance_profile" {
  name_prefix = "${var.vault_cluster_name}-"
  path        = "/"
  role        = aws_iam_role.vault_instance_role.name

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "vault_instance_role" {
  name_prefix        = "${var.vault_cluster_name}-"
  assume_role_policy = data.aws_iam_policy_document.instance_role.json

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_policy" "vault_unseal_kms_key_use" {
  name_prefix = "unseal-key-use-"
  path        = "/"
  description = "Vault unseal kms key use policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Effect   = "Allow"
        Resource = [data.aws_kms_alias.vault_unseal_key.target_key_arn]
      },
    ]
  })
}

resource "aws_iam_policy" "vault_auto_discover_consul_cluster" {
  name_prefix = "auto-discover-consul-cluster-"
  path        = "/"
  description = "Vault discover consul cluster policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
        ]
        Effect   = "Allow"
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vault_unseal_key_role_policy_attach" {
  role       = aws_iam_role.vault_instance_role.name
  policy_arn = aws_iam_policy.vault_unseal_kms_key_use.arn
}

resource "aws_iam_role_policy_attachment" "vault_auto_discover_consul_cluster_policy_attach" {
  role       = aws_iam_role.vault_instance_role.name
  policy_arn = aws_iam_policy.vault_auto_discover_consul_cluster.arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Consul
# ---------------------------------------------------------------------------------------------------------------------

data "template_file" "user_data_consul_cluster" {
  template = file("user-data-consul.sh")

  vars = {
    aws_region               = var.region
    aws_endpoint_name_suffix = var.endpoint_name_suffix
    aws_endpoint_url_suffix  = var.endpoint_url_suffix
    consul_cluster_tag_key   = var.consul_cluster_tag_key
    consul_cluster_tag_value = var.consul_cluster_name
  }
}

resource "aws_autoscaling_group" "consul_autoscaling_group" {
  name_prefix = "${var.consul_cluster_name}-"

  launch_template {
    id      = aws_launch_template.consul_launch_template.id
    version = "$Latest"
  }

  vpc_zone_identifier = data.aws_subnet_ids.subnet.ids

  # Use a fixed-size cluster
  min_size             = var.consul_cluster_size
  max_size             = var.consul_cluster_size
  desired_capacity     = var.consul_cluster_size

  health_check_type         = "EC2"
  health_check_grace_period = 300
  wait_for_capacity_timeout = "5m"

  tags = flatten(
    [
      {
        key                 = "Name"
        value               = var.consul_cluster_name
        propagate_at_launch = true
      },
      {
        key                 = var.consul_cluster_tag_key
        value               = var.consul_cluster_name
        propagate_at_launch = true
      }
    ]
  )

  lifecycle {
    create_before_destroy = true
    ignore_changes = [load_balancers, target_group_arns]
  }

  depends_on = [
      aws_security_group_rule.consul_allow_all_outbound,
      aws_security_group_rule.consul_allow_dns_tcp_inbound,
      aws_security_group_rule.consul_allow_dns_udp_inbound,
      aws_security_group_rule.consul_allow_ssh_inbound_from_cidr_blocks,
      aws_security_group_rule.consul_allow_server_rpc_inbound_from_self,
      aws_security_group_rule.consul_allow_cli_rpc_inbound_from_self,
      aws_security_group_rule.consul_allow_serf_lan_tcp_inbound_from_self,
      aws_security_group_rule.consul_allow_serf_lan_udp_inbound_from_self,
      aws_security_group_rule.consul_allow_serf_wan_tcp_inbound_from_self,
      aws_security_group_rule.consul_allow_serf_wan_udp_inbound_from_self,
      aws_security_group_rule.consul_allow_http_api_inbound_from_self,
      aws_security_group_rule.consul_allow_https_api_inbound_from_self,
      aws_security_group_rule.consul_allow_dns_tcp_inbound_from_self,
      aws_security_group_rule.consul_allow_dns_udp_inbound_from_self,
      aws_security_group_rule.consul_allow_serf_lan_tcp_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_serf_lan_udp_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_server_rpc_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_cli_rpc_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_http_api_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_https_api_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_dns_tcp_inbound_from_security_group_ids,
      aws_security_group_rule.consul_allow_dns_udp_inbound_from_security_group_ids
  ]
}

resource "aws_launch_template" "consul_launch_template" {
  name_prefix   = "${var.consul_cluster_name}-"
  image_id      = var.ami_id
  instance_type = var.consul_instance_type
  user_data     = base64encode(data.template_file.user_data_consul_cluster.rendered)

  iam_instance_profile {
    name = aws_iam_instance_profile.consul_instance_profile.name
  }
  key_name = var.ssh_key_name

  network_interfaces {
    associate_public_ip_address = var.associate_public_ips
    delete_on_termination = true
    security_groups = [aws_security_group.consul_launch_template_security_group.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      delete_on_termination = true
      volume_size = 10
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "consul_launch_template_security_group" {
  name_prefix = "${var.consul_cluster_name}-"
  description = "Security group for the ${var.consul_cluster_name} launch template"
  vpc_id      = data.aws_vpc.vpc.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    "Name" = var.consul_cluster_name
  }
}

resource "aws_security_group_rule" "consul_allow_all_outbound" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_tcp_inbound" {
  type        = "ingress"
  from_port   = var.consul_dns_port
  to_port     = var.consul_dns_port
  protocol    = "tcp"
  cidr_blocks = [data.aws_vpc.vpc.cidr_block]

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_udp_inbound" {
  type        = "ingress"
  from_port   = var.consul_dns_port
  to_port     = var.consul_dns_port
  protocol    = "udp"
  cidr_blocks = [data.aws_vpc.vpc.cidr_block]

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_ssh_inbound_from_cidr_blocks" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [data.aws_vpc.vpc.cidr_block]

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_server_rpc_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_server_rpc_port
  to_port   = var.consul_server_rpc_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_cli_rpc_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_cli_rpc_port
  to_port   = var.consul_cli_rpc_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_lan_tcp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_serf_lan_port
  to_port   = var.consul_serf_lan_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_lan_udp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_serf_lan_port
  to_port   = var.consul_serf_lan_port
  protocol  = "udp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_wan_tcp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_serf_wan_port
  to_port   = var.consul_serf_wan_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_wan_udp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_serf_wan_port
  to_port   = var.consul_serf_wan_port
  protocol  = "udp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_http_api_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_http_api_port
  to_port   = var.consul_http_api_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_https_api_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_https_api_port
  to_port   = var.consul_https_api_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_tcp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_dns_port
  to_port   = var.consul_dns_port
  protocol  = "tcp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_udp_inbound_from_self" {
  type      = "ingress"
  from_port = var.consul_dns_port
  to_port   = var.consul_dns_port
  protocol  = "udp"
  self      = true

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_lan_tcp_inbound_from_security_group_ids" {
  type      = "ingress"
  from_port = var.consul_serf_lan_port
  to_port   = var.consul_serf_lan_port
  protocol  = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_serf_lan_udp_inbound_from_security_group_ids" {
  type      = "ingress"
  from_port = var.consul_serf_lan_port
  to_port   = var.consul_serf_lan_port
  protocol  = "udp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_server_rpc_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_server_rpc_port
  to_port                  = var.consul_server_rpc_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_cli_rpc_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_cli_rpc_port
  to_port                  = var.consul_cli_rpc_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_http_api_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_http_api_port
  to_port                  = var.consul_http_api_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_https_api_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_https_api_port
  to_port                  = var.consul_https_api_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_tcp_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_dns_port
  to_port                  = var.consul_dns_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_security_group_rule" "consul_allow_dns_udp_inbound_from_security_group_ids" {
  type                     = "ingress"
  from_port                = var.consul_dns_port
  to_port                  = var.consul_dns_port
  protocol                 = "udp"
  source_security_group_id = aws_security_group.vault_launch_template_security_group.id

  security_group_id = aws_security_group.consul_launch_template_security_group.id
}

resource "aws_iam_instance_profile" "consul_instance_profile" {
  name_prefix = "${var.consul_cluster_name}-"
  path        = "/"
  role        = aws_iam_role.consul_instance_role.name

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "consul_instance_role" {
  name_prefix        = "${var.consul_cluster_name}-"
  assume_role_policy = data.aws_iam_policy_document.instance_role.json

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_policy" "consul_auto_discover_cluster" {
  name_prefix = "auto-discover-cluster-"
  path        = "/"
  description = "Vault unseal consul auto discover cluster policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "autoscaling:DescribeAutoScalingGroups",
        ]
        Effect   = "Allow"
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "consul_auto_discover_cluster_attach" {
  role       = aws_iam_role.consul_instance_role.name
  policy_arn = aws_iam_policy.consul_auto_discover_cluster.arn
}
