
Add descriptions for all security groups

```hcl
resource "aws_security_group" "good_example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group

 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule

