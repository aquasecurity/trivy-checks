
Enable master authorized networks or DNS-based endpoints

```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.10.128.0/24"
      display_name = "internal"
    }
  }
}
```
```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = true
    }
    ip_endpoints_config {
      enabled = false
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#

