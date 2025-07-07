
Enable master authorized networks

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

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#

