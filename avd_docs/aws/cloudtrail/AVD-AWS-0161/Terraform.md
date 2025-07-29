
Restrict public access to the S3 bucket

```hcl
resource "aws_cloudtrail" "good_example" {
  s3_bucket_name = aws_s3_bucket.example.id
}

resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl    = "private"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail

