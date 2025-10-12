resource "aws_eip" "this" {
  domain = "vpc"
  tags = {
    Name = "${var.name}nat-gw"
  }
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.this.id
  subnet_id     = var.subnet.id
  tags = {
    Name = var.name
  }
}

resource "aws_route" "this" {
  for_each = var.route_tables

  nat_gateway_id         = aws_nat_gateway.this.id
  destination_cidr_block = "0.0.0.0/0"
  route_table_id         = each.value.id
}
