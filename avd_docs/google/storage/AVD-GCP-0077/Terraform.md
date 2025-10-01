
Enable Access and Storage logs for Cloud Storage buckets by configuring a log sink or specifying a `log_bucket` in Terraform.


```hcl
# Bucket with logging configured
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
```hcl
# Multiple buckets where log bucket doesn't need its own logging
resource "google_storage_bucket" "application_bucket" {
  name                        = "my-app-bucket"
  location                    = "EU"
  force_destroy               = true
  uniform_bucket_level_access = true

  logging {
    log_bucket = "my-log-bucket"
  }
}

resource "google_storage_bucket" "log_bucket" {
  name                        = "my-log-bucket"
  location                    = "EU"
  force_destroy               = true
  uniform_bucket_level_access = true
  # No logging required since this bucket is used as a log bucket
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#logging

