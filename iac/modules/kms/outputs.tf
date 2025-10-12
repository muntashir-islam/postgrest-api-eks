output "key" {
  description = "KMS Key object"
  value       = aws_kms_key.this
}

output "alias" {
  description = "KMS Alias object"
  value       = aws_kms_alias.this
}
