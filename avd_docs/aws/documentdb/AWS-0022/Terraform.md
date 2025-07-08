
Enable encryption using customer managed keys

```hcl
resource "aws_kms_key" "docdb_encryption" {
  enable_key_rotation = true
}

resource "aws_docdb_cluster" "docdb" {
  cluster_identifier = "my-docdb-cluster"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  kms_key_id         = aws_kms_key.docdb_encryption.arn
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id

