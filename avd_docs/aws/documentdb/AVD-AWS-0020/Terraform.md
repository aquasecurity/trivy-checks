
Enable export logs

```hcl
resource "aws_docdb_cluster" "good_example" {
  cluster_identifier              = "my-docdb-cluster"
  master_username                 = "foo"
  master_password                 = "mustbeeightchars"
  enabled_cloudwatch_logs_exports = "audit"
}
```
```hcl
resource "aws_docdb_cluster" "good_example" {
  cluster_identifier              = "my-docdb-cluster"
  master_username                 = "foo"
  master_password                 = "mustbeeightchars"
  enabled_cloudwatch_logs_exports = "profiler"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#enabled_cloudwatch_logs_exports

