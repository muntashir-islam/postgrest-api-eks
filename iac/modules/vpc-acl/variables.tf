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

variable "subnets" {
  type = map(object({
    id = string
  }))
  description = "Subnet resources attached to ACL"
  default     = {}
  validation {
    condition     = alltrue([for x in var.subnets : can(regex("^subnet-[a-z0-9]+$", x.id))])
    error_message = "Invalid VPC Subnet ID provided"
  }
}

variable "rules" {
  type = map(object({
    number    = number
    action    = string
    direction = string
    ipv4_cidr = optional(string)
    ipv6_cidr = optional(string)
    protocol  = string
    from_port = number
    to_port   = number
    icmp_code = optional(number)
    icmp_type = optional(number)
  }))
  description = "ACL Rules"
}
