
Remove default firewall rules that allow broad access. Implement custom firewall rules that only allow necessary traffic from specific sources.


```hcl
resource "google_compute_firewall" "good_example" {
  name    = "custom-web-access"
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
resource "google_compute_firewall" "custom-ssh-access" {
  name    = "custom-ssh-access"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["192.168.1.0/24"]
  target_tags   = ["ssh-allowed"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#name

