
Enable server side encryption with a customer managed key

```hcl
resource "aws_kms_key" "dynamo_db_kms" {
  enable_key_rotation = true
}

resource "aws_dynamodb_table" "good_example" {
  name = "example"
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamo_db_kms.key_id
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption

