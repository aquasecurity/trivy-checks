
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
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_alias.trail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id

