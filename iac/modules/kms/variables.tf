variable "name" {
  type        = string
  description = "Name to assign KMS key alias"
}

variable "enabled_service_identifiers" {
  type        = set(string)
  description = "AWS service identifiers that are allowed to use the KMS key."
  default = [
    "events.amazonaws.com",
    "ecs.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "cloudwatch.amazonaws.com",
    "logging.s3.amazonaws.com",
    "logdelivery.elb.amazonaws.com",
    "logdelivery.elasticloadbalancing.amazonaws.com",
    "delivery.logs.amazonaws.com",
    "logs.amazonaws.com"
  ]
}

variable "enabled_cloudwatch_log_delivery" {
  type        = bool
  description = "Allow AWS CloudWatch Logs to use the KMS key during log delivery."
  default     = true
}

variable "enabled_route53_dnssec" {
  type        = bool
  description = "Allow AWS Route53 DNSSEC activities"
  default     = false
}

variable "enabled_route53_dnssec_cloudwatch_logs" {
  type        = bool
  description = "Add CloudWatch log group ARN for DNSSEC log delivery"
  default     = false
}

variable "enable_asg_disk_encryption" {
  type        = bool
  description = "Allow AutoScaling to use the KMS key for EBS volume encryption"
  default     = false
}


variable "additional_cloudwatch_log_delivery_arns" {
  type        = list(string)
  description = "Additional CloudWatch Log ARNs the CloudWatch service can deliver to"
  default     = []
  validation {
    condition = (
      length(var.additional_cloudwatch_log_delivery_arns) == 0
      || alltrue([for x in var.additional_cloudwatch_log_delivery_arns : startswith(x, "arn:${data.aws_partition.this.partition}:logs:${data.aws_region.this.name}:${data.aws_caller_identity.this.account_id}")])
    )
    error_message = "Invalid CloudWatch Logs ARN"
  }
}

variable "enable_iam_permissions" {
  type        = bool
  description = "Allow IAM policies to manage access to KMS key."
  default     = true
}

variable "delete_hold" {
  type        = number
  description = "Amount of days to allow the key to be restored after initiating a delete."
  default     = 30
  validation {
    condition     = var.delete_hold >= 7 && var.delete_hold <= 30
    error_message = "Value must be between 7 and 30."
  }
}

variable "enable_key_rotation" {
  type        = bool
  description = "Enable automatic key rotation."
  default     = true
}

variable "key_rotation_days" {
  type        = number
  description = "Set amount of days before a key is rotated."
  default     = 365
  validation {
    condition     = var.key_rotation_days >= 90 && var.key_rotation_days <= 2560
    error_message = "Value must be between 90 and 2560"
  }
}

variable "custom_key_policy" {
  description = "value"
  type = map(object({
    actions        = set(string)
    principal_type = string
    identifiers    = set(string)
    resources      = set(string)
    conditions = optional(map(object({
      test     = string
      values   = set(string)
      variable = string
    })))
  }))
  default = null
}

variable "key_spec" {
  description = "Key spec encryption/signing algorithm"
  type        = string
  default     = "SYMMETRIC_DEFAULT"
  validation {
    condition     = contains(["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096", "HMAC_256", "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1"], var.key_spec)
    error_message = "Invalid master key spec option: SYMMETRIC_DEFAULT, RSA_2048, RSA_3072, RSA_4096, HMAC_256, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, or ECC_SECG_P256K1."
  }
}

variable "key_usage" {
  description = "Key usage type"
  type        = string
  default     = "ENCRYPT_DECRYPT"
  validation {
    condition     = contains(["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"], var.key_usage)
    error_message = "Invalid key usage type: ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC"
  }
}

variable "enable_guardduty" {
  description = "If true, allows GuardDuty to use the CMK to encrypt findings"
  type        = bool
  default     = false
}

variable "enable_aws_config_kms" {
  description = "If true, allows AWS Config to use the CMK to encrypt snaphost/history resource configuration"
  type        = bool
  default     = false
}

variable "enable_aws_backup" {
  description = "If true, allows AWS Backup to use the CMK to encrypt backups"
  type        = bool
  default     = false
}
