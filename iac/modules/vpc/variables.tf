variable "name" {
  type        = string
  description = "Resource name prefix"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,31}$", var.name))
    error_message = "Must start with a letter, all alpha characters lower case, max character length of 32 and only use the following characters: a-z0-9-"
  }
}

variable "cidr" {
  description = "VPC CIDR, please don't over lap between environments"
  type        = string
  default     = "10.0.0.0/20"
  validation {
    condition     = endswith(var.cidr, "/20") && cidrsubnet(var.cidr, 0, 0) == var.cidr
    error_message = "CIDR must be a /20 and set to the first IP address in that subnet."
  }
}

variable "flow_log_retention" {
  type        = number
  description = "CloudWatch Log group retention in days"
  default     = 365
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.flow_log_retention
    )
    error_message = "Log rention must be on of: 0 1 3 5 7 14 30 60 90 120 150 180 365 400 545 731 1096 1827 2192 2557 2922 3288 3653."
  }
}

variable "flow_log_traffic" {
  type        = string
  description = "What type of traffic to log in VPC flow logs"
  default     = "REJECT"
  validation {
    condition     = contains(["ALL", "REJECT", "ACCEPT"], upper(var.flow_log_traffic))
    error_message = "Value must be one of: ALL, REJECT, ACCEPT."
  }
}

variable "cloudwatch_flow_logs" {
  type        = bool
  description = "Enable CloudWatch VPC flow logs"
  default     = false
}

variable "s3_flow_logs" {
  type = object({
    arn = string
  })
  description = "Enabled S3 VPC flow logs"
  default     = null
  validation {
    condition     = var.s3_flow_logs == null ? true : can(regex("^arn:${data.aws_partition.this.partition}:s3:::[a-z0-9\\.\\-]{1,64}", var.s3_flow_logs.arn))
    error_message = "Invalid S3 ARN in object"
  }
}

variable "flow_log_agg" {
  type        = number
  description = "Amount of time in seconds to wait for VPC flow log aggregation."
  default     = 60
  validation {
    condition     = var.flow_log_agg >= 60 && var.flow_log_agg <= 600
    error_message = "Value must be between 60 and 600."
  }
}

variable "kms" {
  type = object({
    arn = string
  })
  description = "KMS CMK key or alias used to encrypt bucket contents."
  validation {
    condition = can(regex(
      "^arn:${data.aws_partition.this.partition}:kms:${data.aws_region.this.name}:${data.aws_caller_identity.this.account_id}:(key/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}|alias/[a-zA-Z0-9_\\-/]{1,256})$",
      var.kms.arn
    ))
    error_message = "Invalid KMS ARN in supplied object."
  }
}
