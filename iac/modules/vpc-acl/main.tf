resource "aws_network_acl" "this" {
  # checkov:skip=CKV2_AWS_1 NACL attachment check fails when subnet is referenced as a var: https://github.com/bridgecrewio/checkov/issues/1571
  vpc_id     = var.vpc.id
  subnet_ids = [for x in var.subnets : x.id]

  dynamic "egress" {
    for_each = { for k, v in var.rules : k => v if v.direction == "egress" }

    content {
      rule_no         = egress.value.number
      action          = egress.value.action
      cidr_block      = egress.value.ipv4_cidr
      ipv6_cidr_block = egress.value.ipv6_cidr
      protocol        = egress.value.protocol
      from_port       = egress.value.from_port
      to_port         = egress.value.to_port
      icmp_code       = coalesce(egress.value.icmp_code, 0)
      icmp_type       = coalesce(egress.value.icmp_type, 0)
    }
  }

  dynamic "ingress" {
    for_each = { for k, v in var.rules : k => v if v.direction == "ingress" }

    content {
      rule_no         = ingress.value.number
      action          = ingress.value.action
      cidr_block      = ingress.value.ipv4_cidr
      ipv6_cidr_block = ingress.value.ipv6_cidr
      protocol        = ingress.value.protocol
      from_port       = ingress.value.from_port
      to_port         = ingress.value.to_port
      icmp_code       = coalesce(ingress.value.icmp_code, 0)
      icmp_type       = coalesce(ingress.value.icmp_type, 0)
    }
  }

  tags = {
    Name = var.name
  }
}
