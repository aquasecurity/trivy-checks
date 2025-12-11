
Enable StackDriver monitoring

```hcl
resource "google_container_cluster" "good_example" {
  name               = "my-gke-cluster"
  location           = "us-central1"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#monitoring_service

