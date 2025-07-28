
Configure IAM Audit Logs for required services and log types. In Terraform, use `google_project_iam_audit_config` to specify the services and log types (ADMIN_READ, DATA_READ, DATA_WRITE) to be audited.


```hcl
resource "google_project_iam_audit_config" "config" {
  project = "your-project-id"
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
```
```hcl
resource "google_project_iam_audit_config" "config" {
  project = "your-project-id"
  service = "cloudresourcemanager.googleapis.com"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
    exempted_members = [
      "serviceAccount:specific-service@project.iam.gserviceaccount.com",
    ]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_audit_config

