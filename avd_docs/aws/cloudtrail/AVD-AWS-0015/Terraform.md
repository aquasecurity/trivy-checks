
Use Customer managed key

```hcl
resource "aws_kms_key" "trail" {
  enable_key_rotation = true
}
resource "aws_kms_alias" "trail" {
  name          = "alias/trail"
  target_key_id = aws_kms_key.trail.key_id
}

resource "aws_cloudtrail" "good_example" {
  kms_key_id = aws_kms_alias.trail.arn
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id

