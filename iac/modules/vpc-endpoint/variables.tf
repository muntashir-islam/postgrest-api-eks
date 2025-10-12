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

variable "endpoint_service" {
  type        = string
  description = "Endpoint service name (eg: com.amazonaws._region_._service_)"
}

variable "endpoint_type" {
  type        = string
  description = "VPC endpint type"
  default     = "interface"
  validation {
    condition     = contains(["interface", "gateway"], lower(var.endpoint_type))
    error_message = "Only Gateway and Interface endpoint types supported"
  }

  validation {
    condition     = lower(var.endpoint_type) == "interface" ? true : can(regex("^.*\\.(dynamodb|s3|s3express)$", var.endpoint_service))
    error_message = "Gateway endpoints can only be for services: dynamodb, s3, s3express"
  }
}

variable "gateway_route_tables" {
  type = map(object({
    id = string
  }))
  description = "For Gateway endppoints, route tables where endpoint should be attached"
  default     = null
  validation {
    condition     = var.endpoint_type == "gateway" ? var.gateway_route_tables != null : true
    error_message = "gateway_route_tables must be set if endpoint_type is gateway"
  }
  validation {
    condition     = var.gateway_route_tables == null ? true : alltrue([for x in var.gateway_route_tables : can(regex("^rtb-[a-z0-9]+$", x.id))])
    error_message = "Invalid Route Table ID provided"
  }
}

variable "allowed_subnets" {
  type = list(object({
    id                = string
    cidr_block        = string
    availability_zone = string
  }))
  description = "Subnet resources allowed to access the endpoint"
  default     = []
  validation {
    condition     = alltrue([for x in var.allowed_subnets : can(regex("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$", x.cidr_block))])
    error_message = "Invalid CIDR address provided"
  }
  validation {
    condition     = alltrue([for x in var.allowed_subnets : can(regex("^subnet-[a-z0-9]+$", x.id))])
    error_message = "Invalid VPC Subnet ID provided"
  }
}

variable "excluded_azs" {
  type        = list(string)
  description = "Availability zones to exclude when placing the VPC endpoint in the subnets."
  default     = []
}
