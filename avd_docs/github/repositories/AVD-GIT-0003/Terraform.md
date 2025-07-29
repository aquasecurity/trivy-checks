
Enable vulnerability alerts

```hcl
resource "github_repository" "good_example" {
  name                 = "example"
  vulnerability_alerts = true
}
```
```hcl
resource "github_repository" "good_example" {
  name                 = "example"
  archived             = true
  vulnerability_alerts = false
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository

