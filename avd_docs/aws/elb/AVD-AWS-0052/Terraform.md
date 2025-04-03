
Set drop_invalid_header_fields to true

```hcl
resource "aws_alb" "good_example" {
  drop_invalid_header_fields = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields

