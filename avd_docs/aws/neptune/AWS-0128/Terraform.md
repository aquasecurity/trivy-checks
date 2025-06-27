
Enable encryption using customer managed keys

```hcl
resource "aws_neptune_cluster" "good_example" {
  kms_key_arn = "test"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted

