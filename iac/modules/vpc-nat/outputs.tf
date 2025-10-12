output "eips" {
  description = "Provisioned Elastic IPs"
  value       = aws_eip.this
}

output "gw" {
  description = "NAT Gateway"
  value       = aws_nat_gateway.this
}
