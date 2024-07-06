resource "aws_vpc" "example" {
  cidr_block = "10.1.0.0/16"
  tags = {
    Name = "my-vpc-resource"
  }
}