
Restrict RDP (TCP port 3389) ingress in firewall rules. Only allow trusted IP ranges or use Identity-Aware Proxy for RDP access.


```hcl
resource "google_compute_firewall" "good_example_restricted_source" {
  name          = "allow-specific-ip"
  network       = google_compute_network.my_vpc.name
  direction     = "INGRESS"
  source_ranges = ["1.2.3.4/32"]
  allow {
    protocol = "tcp"
    ports    = ["3380-3390"]
  }
}
```
```hcl
resource "google_compute_firewall" "good_example_different_port" {
  name          = "allow-vms-to-some-machine"
  network       = google_compute_network.my_vpc.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["8080-8090"]
  }
}
```
```hcl
resource "google_compute_firewall" "good_example_with_tags" {
  name          = "allow-tagged-vms"
  network       = google_compute_network.my_vpc.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  source_tags   = ["vms"]
  target_tags   = ["some-machine"]
  allow {
    protocol = "tcp"
    ports    = ["3380-3390"]
  }
}
```
```hcl
resource "google_compute_firewall" "good_example_different_protocol" {
  name          = "allow-udp-3389"
  network       = google_compute_network.my_vpc.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "udp"
    ports    = ["3380-3390"]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges

 - https://www.terraform.io/docs/providers/google/r/compute_firewall.html

