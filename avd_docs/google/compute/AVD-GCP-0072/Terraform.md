
Modify firewall rules that allow all ports to restrict to only required ports. Use separate rules for specific port ranges as needed, instead of a single overly broad rule.


```hcl
resource "google_compute_firewall" "good_example" {
  name    = "allow-specific-ports"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-servers"]
}
```
```hcl
resource "google_compute_firewall" "allow-ssh-and-http" {
  name    = "allow-ssh-and-http"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }

  source_ranges = ["192.168.1.0/24"]
  target_tags   = ["servers"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#allow

