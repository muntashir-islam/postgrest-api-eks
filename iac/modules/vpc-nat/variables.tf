variable "name" {
  type        = string
  description = "Resource name prefix"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,31}$", var.name))
    error_message = "Must start with a letter, all alpha characters lower case, max character length of 32 and only use the following characters: a-z0-9-"
  }
}

variable "subnet" {
  type = object({
    id = string
  })
  description = "Subnet resource where NAT Gateway will be provisioned"
  validation {
    condition     = can(regex("^subnet-[a-z0-9]+$", var.subnet.id))
    error_message = "Invalid Subnet resource ID format"
  }
}

variable "route_tables" {
  type = map(object({
    id = string
  }))
  description = "Route table resources that will have a default route pointing to the NAT Gateway"
  validation {
    condition     = alltrue([for x in var.route_tables : can(regex("^rtb-[a-z0-9]+$", x.id))])
    error_message = "Invalid Route Table resource ID format"
  }
}
