
Enable flow logs for VPC

```hcl
resource "aws_vpc" "example" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "example" {
  log_group_name = "example"
  traffic_type   = "ALL"
  vpc_id         = aws_vpc.example.id
}
```


