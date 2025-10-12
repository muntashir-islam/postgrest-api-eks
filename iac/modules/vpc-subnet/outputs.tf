output "subnets" {
  description = "VPC Subnets"
  value       = aws_subnet.this
}

output "ipv4_gw" {
  description = "IPv4 Internet Gateway"
  value       = var.ipv4_gw == true ? aws_internet_gateway.this[0] : null
}

output "ipv6_gw" {
  description = "IPv6 Internet Gateway"
  value       = var.ipv6_gw == true ? aws_egress_only_internet_gateway.this[0] : null
}

output "route_tables" {
  description = "Route Tables associated to the subnets"
  value       = aws_route_table.this
}
