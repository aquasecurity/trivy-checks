
Use service account or OAuth for authentication

```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_auth

