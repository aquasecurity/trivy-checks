
Enable Private Google Access on subnets. In Terraform, set `private_ip_google_access = true` in the `google_compute_subnetwork` resource.


```hcl
resource "google_compute_subnetwork" "good_example" {
  name                     = "test-subnetwork"
  ip_cidr_range            = "10.2.0.0/16"
  region                   = "us-central1"
  network                  = google_compute_network.custom-test.id
  private_ip_google_access = true
}
resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#private_ip_google_access

