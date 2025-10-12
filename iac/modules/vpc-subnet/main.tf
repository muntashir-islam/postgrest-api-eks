data "aws_availability_zones" "available" {
  state         = "available"
  exclude_names = var.excluded_azs
}

locals {
  # Below we sort the availability zones to avoid non-determinism, as the data block isn't guaranteed to be sorted
  available_azs_sorted = sort(data.aws_availability_zones.available.names)
  az_subset            = slice(local.available_azs_sorted, 0, var.az_count) # Will give out of bounds error if not enough AZs are available

  # In the loop I'm creating a new object instead of using the merge function because otherwise the language
  # server isn't able to properly infer types through static analysis
  subnet_definitions_with_az = [
    for index, subnet_definition in var.subnet_definitions : {
      ipv4_cidr = subnet_definition.ipv4_cidr
      ipv6_cidr = subnet_definition.ipv6_cidr
      # Loops through all availability zones, for example if there are 4 subnets and three zones [a, b, c]
      # then it would loop back [a, b, c, a]
      az = local.az_subset[index % length(local.az_subset)]
    }
  ]
}

resource "aws_subnet" "this" {
  for_each = { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x }
  vpc_id   = var.vpc.id

  cidr_block        = each.value.ipv4_cidr
  ipv6_cidr_block   = each.value.ipv6_cidr
  availability_zone = each.value.az

  tags = {
    Name = "${var.name}-${each.value.az}-${coalesce(each.value.ipv4_cidr, each.value.ipv6_cidr)}"
    Type = var.ipv4_gw ? "Public" : "Private"
  }
}

resource "aws_internet_gateway" "this" {
  count = var.ipv4_gw == true ? 1 : 0

  vpc_id = var.vpc.id

  tags = {
    Name = "${var.name}-ipv4-gw"
  }
}

resource "aws_egress_only_internet_gateway" "this" {
  count = var.ipv6_gw == true ? 1 : 0

  vpc_id = var.vpc.id
  tags = {
    Name = "${var.name}-ipv6-gw"
  }
}

resource "aws_route_table" "this" {
  for_each = { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x }

  vpc_id = var.vpc.id

  tags = {
    Name = "${var.name}-${each.value.az}-${each.key}"
  }
}

resource "aws_route_table_association" "this" {
  for_each = { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x }

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.this[each.key].id
}

resource "aws_route" "ipv4_gw" {
  for_each = var.ipv4_gw != true ? {} : { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x }

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

# resource "aws_route" "ipv6_gw" {
#   for_each = var.ipv6_gw != true ? {} : { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x }

#   route_table_id              = aws_route_table.this[each.key].id
#   destination_ipv6_cidr_block = "::/0"
#   egress_only_gateway_id      = aws_egress_only_internet_gateway.this[0].id
# }

resource "aws_route" "ipv6_gw" {
  for_each = var.ipv6_gw ? { for x in local.subnet_definitions_with_az : coalesce(x.ipv4_cidr, x.ipv6_cidr) => x } : {}

  route_table_id              = aws_route_table.this[each.key].id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = length(aws_egress_only_internet_gateway.this) > 0 ? aws_egress_only_internet_gateway.this[0].id : null
}
