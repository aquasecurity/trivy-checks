
Explicitly set the retention period to greater than the default

```hcl
resource "nifcloud_db_instance" "good_example" {
  instance_class          = "db.large8"
  backup_retention_period = 5
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period

