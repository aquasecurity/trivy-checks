
Enable encryption of Neptune storage

```hcl
resource "aws_neptune_cluster" "good_example" {
  kms_key_arn       = "test"
  storage_encrypted = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted

