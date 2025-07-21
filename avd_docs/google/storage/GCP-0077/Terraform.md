
Enable Access and Storage logs for Cloud Storage buckets by configuring a log sink or specifying a `log_bucket` in Terraform.


```hcl
resource "google_storage_bucket" "default" {
  name                        = "my-default-bucket"
  location                    = "EU"
  force_destroy               = true
  uniform_bucket_level_access = true

  logging {
    log_bucket = "my-log-bucket"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#logging

