
Enable in transit encryption for replication group

```hcl
resource "aws_elasticache_replication_group" "good_example" {
  transit_encryption_enabled = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled

