
Add descriptions for all security groups and rules

```hcl
resource "aws_elasticache_security_group" "good_example" {
  description = "something"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_security_group#description

