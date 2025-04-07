
Root and user volume encryption should be enabled

```hcl
resource "aws_workspaces_workspace" "good_example" {
  root_volume_encryption_enabled = true
  user_volume_encryption_enabled = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled

