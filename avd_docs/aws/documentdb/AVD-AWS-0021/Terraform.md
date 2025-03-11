
Enable storage encryption

```hcl
resource "aws_docdb_cluster" "good_example" {
  cluster_identifier = "my-docdb-cluster"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  storage_encrypted  = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#storage_encrypted

