
Limit firewall rules to necessary port ranges only. If a wide range is specified, consider splitting into smaller ranges or specific ports needed for your application.


```hcl
resource "google_compute_firewall" "good_example_specific_ports" {
  name      = "allow-specific-ports"
  network   = "default"
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080"]
  }
  source_ranges = ["0.0.0.0/0"]
}
```
```hcl
resource "google_compute_firewall" "good_example_small_range" {
  name      = "allow-small-range"
  network   = "default"
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["8000-8010"] # 10 ports
  }
  source_ranges = ["10.0.0.0/16"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#allow

 - https://cloud.google.com/vpc/docs/using-firewalls

