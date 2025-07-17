
Use limited permissions for service accounts to be effective

```hcl
resource "google_container_cluster" "good_example" {
  node_config {
    service_account = "cool-service-account@example.com"
  }
}
```
```hcl
resource "google_container_cluster" "good_example" {
  cluster_autoscaling {
    enabled = true
    auto_provisioning_defaults {
      service_account = "cool-service-account@example.com"
    }
  }
}
```
```hcl
resource "google_container_cluster" "good_example" {
  enable_autopilot = true
  cluster_autoscaling {
    auto_provisioning_defaults {
      service_account = "cool-service-account@example.com"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account

