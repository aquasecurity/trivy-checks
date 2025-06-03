
Use SSE-KMS with a customer managed key (CMK)

```hcl
resource "aws_kms_key" "mykey" {}

resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.good_example.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
```
```hcl
resource "aws_s3_bucket" "good_example" {
  # server access logging bucket
  acl    = "log-delivery-write"
  bucket = "mybucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.good_example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```
```hcl
resource "aws_kms_key" "good_example" {
  enable_key_rotation = true
}

resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"

  # deprecated way
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.example.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption

