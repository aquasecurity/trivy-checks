
Use approved organizational email accounts for IAM bindings. Audit IAM policies to replace any personal or unapproved email accounts with proper service accounts or corporate emails.


```hcl
resource "google_project_iam_binding" "good_example" {
  members = [
    "user:employee@company.com",
    "serviceAccount:service@company.iam.gserviceaccount.com",
  ]
}
```
```hcl
resource "google_project_iam_member" "good_example" {
  member = "user:admin@organization.com"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_binding

