
Remove verified record

```hcl
resource "nifcloud_dns_record" "test" {
  zone_id = nifcloud_dns_zone.example.id
  name    = "test"
  type    = "A"
  record  = "some"
}
```
```hcl
resource "nifcloud_dns_record" "test" {
  zone_id = nifcloud_dns_zone.example.id
  name    = "test"
  type    = "TXT"
  record  = "some"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/dns_record

