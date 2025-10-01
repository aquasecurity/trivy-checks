
Disable legacy metadata endpoints

```hcl
resource "google_container_cluster" "good_example" {
  node_config {
    metadata = {
      disable-legacy-endpoints = true
    }
  }
}
```
```hcl
resource "google_container_cluster" "good_example" {
  enable_autopilot = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata

