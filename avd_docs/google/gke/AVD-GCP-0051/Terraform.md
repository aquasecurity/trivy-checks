
Set cluster resource labels

```hcl
resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"
  resource_labels = {
    "env" = "staging"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#resource_labels

