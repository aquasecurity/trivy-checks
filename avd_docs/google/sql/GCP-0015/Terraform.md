
Enforce SSL for all connections

```hcl
# For terraform-provider-google < 6.0.1
resource "google_sql_database_instance" "postgres" {
  name             = "postgres-instance-a"
  database_version = "POSTGRES_11"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = false
      authorized_networks {
        value = "108.12.12.0/24"
        name  = "internal"
      }
      require_ssl = true
    }
  }
}
```
```hcl
# For terraform-provider-google >= 6.0.1
resource "google_sql_database_instance" "postgres" {
  name             = "postgres-instance-a"
  database_version = "POSTGRES_11"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = false
      authorized_networks {
        value = "108.12.12.0/24"
        name  = "internal"
      }
      ssl_mode = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
  }
}
```
```hcl
# For terraform-provider-google >= 6.0.1
resource "google_sql_database_instance" "postgres" {
  name             = "postgres-instance-a"
  database_version = "POSTGRES_11"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = false
      authorized_networks {
        value = "108.12.12.0/24"
        name  = "internal"
      }
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance

