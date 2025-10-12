locals {
  filtered_subnets = [for subnet in var.allowed_subnets : subnet
  if !contains(var.excluded_azs, subnet.availability_zone)]
}

resource "aws_security_group" "this" {
  count       = lower(var.endpoint_type) == "interface" ? 1 : 0
  name        = "${var.name}-sg"
  description = "Security group for VPC endpoint ${var.name}"
  vpc_id      = var.vpc.id
  tags = {
    Name = "${var.name}-sg"
  }
}

resource "aws_vpc_endpoint" "this" {

  private_dns_enabled = lower(var.endpoint_type) == "interface" ? true : false
  route_table_ids     = lower(var.endpoint_type) == "gateway" ? [for x in var.gateway_route_tables : x.id] : null
  service_name        = replace(var.endpoint_service, "__REGION__", data.aws_region.this.name)
  subnet_ids          = lower(var.endpoint_type) == "interface" ? [for x in local.filtered_subnets : x.id] : null
  vpc_endpoint_type   = title(lower(var.endpoint_type))
  vpc_id              = var.vpc.id
  security_group_ids  = lower(var.endpoint_type) == "interface" ? [aws_security_group.this[0].id] : null

  tags = {
    Name = var.name
  }
}
