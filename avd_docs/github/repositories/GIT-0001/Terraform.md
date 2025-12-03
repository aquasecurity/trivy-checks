
Make sensitive or commercially important repositories private

```hcl
resource "github_repository" "good_example" {
  name       = "example"
  visibility = "private"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository

