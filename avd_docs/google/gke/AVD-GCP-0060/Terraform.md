
Enable StackDriver logging

```hcl
resource "google_container_cluster" "good_example" {
  name            = "my-gke-cluster"
  location        = "us-central1"
  logging_service = "logging.googleapis.com/kubernetes"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#logging_service

