resource "aws_vpc" "this" {
  cidr_block = var.cidr

  assign_generated_ipv6_cidr_block = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_network_address_usage_metrics = true

  tags = {
    Name = var.name
  }
}

# Remove all rules from VPC default SG and ACL
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${var.name}-default-sg"
  }
}
resource "aws_default_network_acl" "this" {
  default_network_acl_id = aws_vpc.this.default_network_acl_id

  lifecycle {
    ignore_changes = [subnet_ids]
  }

  tags = {
    Name = "${var.name}-default-acl"
  }
}

# VPC Flow Logs - cloudwatch
resource "aws_cloudwatch_log_group" "this" {
  count = var.cloudwatch_flow_logs == true ? 1 : 0

  name              = "${var.name}-vpc_flow_log-${aws_vpc.this.id}_${var.flow_log_traffic}"
  retention_in_days = var.flow_log_retention
  kms_key_id        = var.kms.arn

  tags = {
    Name = "${var.name}-vpc_flow_log-${aws_vpc.this.id}_${var.flow_log_traffic}"
  }
}
resource "aws_iam_role" "this" {
  count = var.cloudwatch_flow_logs == true ? 1 : 0

  name = "${var.name}-${aws_vpc.this.id}-CloudWatch-VPCFlowLogs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "AssumeFlowLogs"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${var.name}-${aws_vpc.this.id}-CloudWatch-VPCFlowLogs"
  }
}
resource "aws_iam_policy" "this" {
  count = var.cloudwatch_flow_logs == true ? 1 : 0

  name        = "${var.name}-${aws_vpc.this.id}-CloudWatch-VPCFlowLogs"
  description = "Allow VPC Flow Logs to push to CloudWatch"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "VPCFlowLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.this[0].arn}*"
      },
      {
        Sid    = "AllowKMSUse"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = var.kms.arn
      }
    ]
  })
  tags = {
    Name = "${var.name}-${aws_vpc.this.id}-CloudWatch-VPCFlowLogs"
  }
}
resource "aws_iam_role_policy_attachment" "this" {
  count = var.cloudwatch_flow_logs == true ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.this[0].arn
}
resource "aws_flow_log" "cloudwatch" {
  count = var.cloudwatch_flow_logs == true ? 1 : 0

  iam_role_arn             = aws_iam_role.this[0].arn
  log_destination          = aws_cloudwatch_log_group.this[0].arn
  traffic_type             = var.flow_log_traffic
  vpc_id                   = aws_vpc.this.id
  max_aggregation_interval = var.flow_log_agg

  tags = {
    Name = "${var.name}-${aws_vpc.this.id}-cloudwatch"
  }
}

# VPC Flow Logs - S3
resource "aws_flow_log" "s3" {
  count = var.s3_flow_logs != null ? 1 : 0

  log_destination          = var.s3_flow_logs.arn
  log_destination_type     = "s3"
  traffic_type             = var.flow_log_traffic
  vpc_id                   = aws_vpc.this.id
  max_aggregation_interval = var.flow_log_agg

  tags = {
    Name = "${var.name}-${aws_vpc.this.id}-s3"
  }
}
