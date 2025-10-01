
Enable uniform bucket level access to provide a uniform permissioning system.

```hcl
resource "google_storage_bucket" "static-site" {
  name          = "image-store.com"
  location      = "EU"
  force_destroy = true

  uniform_bucket_level_access = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#uniform_bucket_level_access

