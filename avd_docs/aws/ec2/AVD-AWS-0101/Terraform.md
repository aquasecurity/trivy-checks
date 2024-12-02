
Create a non-default vpc for resources to be created in

```hcl
# no aws default vpc present
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc

