
Enable automatic repair

```hcl
resource "google_container_cluster" "primary" {
  name                     = "my-gke-cluster"
  location                 = "us-central1"
  remove_default_node_pool = true
}

resource "google_container_node_pool" "good_example" {
  name    = "my-node-pool"
  cluster = google_container_cluster.primary.id
  management {
    auto_repair = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_repair

