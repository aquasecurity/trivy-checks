
Use specialised service accounts for specific purposes.

```hcl
resource "google_service_account" "test" {
  account_id   = "account123"
  display_name = "account123"
}

resource "google_project_iam_member" "project-123" {
  project = "project-123"
  role    = "roles/whatever"
  member  = "serviceAccount:${google_service_account.test.email}"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam

