
Set the aggregator to cover all regions

```hcl
resource "aws_config_configuration_aggregator" "good_example" {
  name = "example"

  account_aggregation_source {
    account_ids = ["123456789012"]
    all_regions = true
  }
}
```
```hcl
resource "aws_config_configuration_aggregator" "good_example" {
  name = "example"

  organization_aggregation_source {
    role_arn    = "arn:aws:iam::123456789012:role/ConfigAggregatorRole"
    all_regions = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions

