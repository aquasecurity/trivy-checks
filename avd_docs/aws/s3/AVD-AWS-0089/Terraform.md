
Add a logging block to the resource to enable access logging

```hcl
resource "aws_s3_bucket" "this" {
  bucket = "test-bucket"
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "test-log-bucket"
}

resource "aws_s3_bucket_acl" "log_bucket" {
  acl    = "log-delivery-write"
  bucket = aws_s3_bucket.log_bucket.id
}
```
```hcl
resource "aws_s3_bucket" "this" {
  bucket = "test-bucket"
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "test-log-bucket"
}

resource "aws_s3_bucket_acl" "log_bucket" {
  acl    = "log-delivery-write"
  bucket = aws_s3_bucket.log_bucket.id
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket

