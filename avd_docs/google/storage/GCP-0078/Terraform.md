
Enable object versioning on Cloud Storage buckets to preserve older versions of objects. In Terraform, set `versioning { enabled = true }` for the bucket resource.


```hcl
resource "google_storage_bucket" "default" {
  name                        = "my-default-bucket"
  location                    = "EU"
  force_destroy               = true
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#versioning

