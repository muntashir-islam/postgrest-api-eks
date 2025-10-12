output "endpoint" {
  description = "VPC Endpoint Resource"
  value       = aws_vpc_endpoint.this
}

output "security_group" {
  description = "Security Group resource attached to VPC Endpoint"
  value       = lower(var.endpoint_type) == "interface" ? aws_security_group.this : null
}
