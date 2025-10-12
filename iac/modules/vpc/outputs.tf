output "vpc" {
  description = "VPC resource"
  value       = aws_vpc.this
}
output "flow_log_group" {
  description = "CloudWatch Log Group for VPC Flow logs"
  value       = var.cloudwatch_flow_logs == true ? aws_cloudwatch_log_group.this[0] : null
}
