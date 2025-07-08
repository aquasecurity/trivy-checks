
Enable network policy

```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
  network_policy {
    enabled = true
  }
}
```
```hcl
resource "google_container_cluster" "good_example" {
  name             = "my-gke-cluster"
  location         = "us-central1"
  enable_autopilot = true
}
```
```hcl
resource "google_container_cluster" "good_example" {
  name              = "my-gke-cluster"
  location          = "us-central1"
  datapath_provider = "ADVANCED_DATAPATH"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enabled

