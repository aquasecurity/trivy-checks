
Enable DNSSEC

```hcl
resource "google_dns_managed_zone" "good_example" {
  name     = "example-zone"
  dns_name = "example.com."
  dnssec_config {
    state = "on"
  }
}
```
```hcl
resource "google_dns_managed_zone" "good_example" {
  name       = "example-zone"
  dns_name   = "example.com."
  visibility = "private"
  dnssec_config {
    state = "off"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dns_managed_zone#state

