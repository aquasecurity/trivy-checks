
Enable export logs

```hcl
resource "aws_neptune_cluster" "good_example" {
  enable_cloudwatch_logs_exports = ["audit"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#enable_cloudwatch_logs_exports

