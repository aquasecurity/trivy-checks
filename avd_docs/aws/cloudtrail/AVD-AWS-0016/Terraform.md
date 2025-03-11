
Turn on log validation for Cloudtrail

```hcl
resource "aws_cloudtrail" "good_example" {
  enable_log_file_validation = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation

