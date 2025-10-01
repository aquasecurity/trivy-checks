
Enable IP aliasing

```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
  ip_allocation_policy {}
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#ip_allocation_policy

