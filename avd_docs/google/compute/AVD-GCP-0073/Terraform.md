
Replace default firewall rules with custom, more restrictive rules appropriate for your security requirements

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
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall

