variable "name" {
  type        = string
  description = "Resource name prefix"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,31}$", var.name))
    error_message = "Must start with a letter, all alpha characters lower case, max character length of 32 and only use the following characters: a-z0-9-"
  }
}

variable "vpc" {
  type = object({
    id = string
  })
  description = "VPC resource where endpoint is deployed"
  validation {
    condition     = can(regex("^vpc-[a-z0-9]+$", var.vpc.id))
    error_message = "Invalid VPC ID format"
  }
}

variable "ipv4_gw" {
  type        = bool
  description = "Should an IPv4 Internet Gateway be provisioned, will be set as default route"
  default     = false
}

variable "ipv6_gw" {
  type        = bool
  description = "Should an IPv6 Internet Gateway be provisioned, will be set as default route"
  default     = false
}

variable "subnet_definitions" {
  type = list(object({
    ipv4_cidr = optional(string)
    ipv6_cidr = optional(string)
  }))
  description = "Subnets to be created, listing CIDR ranges and AZs"
  validation {
    condition     = alltrue([for x in var.subnet_definitions : x.ipv4_cidr == null ? true : cidrsubnet(x.ipv4_cidr, 0, 0) == x.ipv4_cidr])
    error_message = "Invalid IPv4 CIDR detected"
  }
  validation {
    condition     = alltrue([for x in var.subnet_definitions : x.ipv6_cidr == null ? true : cidrsubnet(x.ipv6_cidr, 0, 0) == x.ipv6_cidr])
    error_message = "Invalid IPv6 CIDR detected"
  }
}

variable "az_count" {
  type        = number
  description = "Number of different AZs to use, if more are available than this number, a subset will automatically be chosen."
  default     = 3
}

variable "excluded_azs" {
  type        = list(string)
  description = "Availability zones to exclude from subnet creation"
  default     = []
}
