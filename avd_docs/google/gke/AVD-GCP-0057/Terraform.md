
Set node metadata to SECURE or GKE_METADATA_SERVER

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
      node_metadata = "SECURE"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata

