
Enforce a minimum TLS version of 1.2

```hcl
resource "google_compute_ssl_policy" "good_example" {
  name            = "production-ssl-policy"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}
```
```hcl
resource "google_compute_ssl_policy" "good_example_tls13" {
  name            = "production-ssl-policy"
  profile         = "RESTRICTED"
  min_tls_version = "TLS_1_3"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_policy#min_tls_version

