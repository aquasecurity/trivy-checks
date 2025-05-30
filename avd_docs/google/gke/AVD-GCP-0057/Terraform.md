
Set mode to GKE_METADATA

```hcl
resource "google_container_cluster" "primary" {
  name     = "my-gke-cluster"
  location = "us-central1"

  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "good_example" {
  cluster = google_container_cluster.primary.id
  node_config {
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata

