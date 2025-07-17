
Configure access permissions with higher granularity

```hcl
resource "google_bigquery_dataset" "good_example" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  location                    = "EU"
  default_table_expiration_ms = 3600000
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_dataset#special_group

