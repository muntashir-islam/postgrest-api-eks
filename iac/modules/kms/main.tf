data "aws_iam_policy_document" "this" {
  policy_id = "Default-Key-Policy"
  dynamic "statement" {
    for_each = var.enable_iam_permissions == true ? [0] : []

    content {
      sid = "Enable IAM User Permissions"
      principals {
        type        = "AWS"
        identifiers = ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:root"]
      }
      actions   = ["kms:*"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.custom_key_policy != null ? var.custom_key_policy : {}

    content {
      sid     = "${replace(statement.key, "[^a-zA-Z0-9]", "")}CustomPolicy"
      actions = statement.value.actions
      principals {
        type        = statement.value.principal_type
        identifiers = statement.value.identifiers
      }
      resources = statement.value.resources
      dynamic "condition" {
        for_each = statement.value.conditions
        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }
    }
  }

  dynamic "statement" {
    for_each = var.enabled_cloudwatch_log_delivery == true ? [0] : []
    content {
      sid = "CloudWatch Access"
      principals {
        type        = "Service"
        identifiers = ["logs.${data.aws_region.this.name}.amazonaws.com"]
      }
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ]
      resources = ["*"]
      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:logs:arn"
        values = concat(
          ["arn:${data.aws_partition.this.partition}:logs:${data.aws_region.this.name}:${data.aws_caller_identity.this.account_id}:*${var.name}*"],
          var.enabled_route53_dnssec_cloudwatch_logs == false ? [] : ["arn:${data.aws_partition.this.partition}:logs:${data.aws_region.this.name}:${data.aws_caller_identity.this.account_id}:log-group:/aws/route53/*"],
          var.additional_cloudwatch_log_delivery_arns
        )
      }
    }
  }
  dynamic "statement" {
    for_each = length(var.enabled_service_identifiers) > 0 ? [true] : []
    content {
      sid = "General AWS Service Access"
      principals {
        type        = "Service"
        identifiers = var.enabled_service_identifiers
      }
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ]
      resources = ["*"]
    }
  }
  dynamic "statement" {
    for_each = var.enabled_route53_dnssec == true ? [0] : []
    content {
      sid = "Route53 DNSSEC Allow Grant"
      principals {
        identifiers = ["dnssec-route53.amazonaws.com"]
        type        = "Service"
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "Bool"
        values   = ["true"]
        variable = "kms:GrantIsForAWSResource"
      }
    }
  }
  dynamic "statement" {
    for_each = var.enabled_route53_dnssec == true ? [0] : []
    content {
      sid = "Route53 DNSSEC Records"
      principals {
        identifiers = ["dnssec-route53.amazonaws.com"]
        type        = "Service"
      }
      actions = [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign"
      ]
      resources = ["*"]
      condition {
        test     = "ArnLike"
        values   = ["arn:${data.aws_partition.this.partition}:route53:::hostedzone/*"]
        variable = "aws:SourceArn"
      }
      condition {
        test     = "StringEquals"
        values   = [data.aws_caller_identity.this.account_id]
        variable = "aws:SourceAccount"
      }
    }
  }
  dynamic "statement" {
    for_each = var.enable_guardduty ? [0] : []
    content {
      sid = "AllowGuardDutyToEncryptFindings"
      principals {
        type        = "Service"
        identifiers = ["guardduty.amazonaws.com"]
      }
      actions = [
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.this.account_id]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:${data.aws_partition.this.partition}:guardduty:${data.aws_region.this.name}:${data.aws_caller_identity.this.account_id}:detector/*"]
      }
    }
  }
  dynamic "statement" {
    for_each = var.enable_aws_config_kms ? [1] : []
    content {
      sid    = "AllowAWSConfigUseOfKey"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["config.${data.aws_partition.this.dns_suffix}"]
      }

      actions = [
        "kms:Encrypt",
        "kms:GenerateDataKey*",
      ]

      resources = ["*"]

      # Tighten to your account
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.this.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_asg_disk_encryption ? [0] : []
    content {
      sid    = "Allow service-linked role use of the customer managed key"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
      }
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_asg_disk_encryption ? [0] : []
    content {
      sid    = "Allow attachment of persistent resources"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
      }
      actions = [
        "kms:CreateGrant"
      ]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = [true]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_aws_backup ? [0] : []
    content {
      sid    = "KmsCreateGrantPermissions"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = ["arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:root"]
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "ForAnyValue:StringEquals"
        variable = "kms:EncryptionContextKeys"
        values   = ["aws:backup:backup-vault"]
      }
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = [true]
      }
      condition {
        test     = "StringLike"
        variable = "kms:ViaService"
        values   = ["backup.*.${data.aws_partition.this.dns_suffix}"]
      }
    }
  }

}

resource "aws_kms_key" "this" {
  description              = "CMK for stack ${var.name}"
  deletion_window_in_days  = var.delete_hold
  enable_key_rotation      = var.enable_key_rotation
  rotation_period_in_days  = var.enable_key_rotation != false ? var.key_rotation_days : null
  policy                   = data.aws_iam_policy_document.this.json
  customer_master_key_spec = var.key_spec
  key_usage                = var.key_usage

  # lifecycle {
  #   ignore_changes = [policy]
  # }

  tags = {
    Name = var.name
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}
