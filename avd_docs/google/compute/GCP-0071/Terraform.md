
Restrict SSH (TCP port 22) access in firewall rules to known IP addresses or ranges. Avoid open 0.0.0.0/0 access for SSH.


```hcl
resource "google_compute_firewall" "good_example" {
  name    = "allow-ssh-from-specific-ip"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["192.168.1.0/24"]
  target_tags   = ["ssh-allowed"]
}
```
```hcl
resource "google_compute_firewall" "allow-ssh-from-office" {
  name    = "allow-ssh-from-office"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["203.0.113.0/24"]
  target_tags   = ["web-servers"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall

