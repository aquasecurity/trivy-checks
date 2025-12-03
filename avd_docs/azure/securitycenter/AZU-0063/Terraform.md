
Enable alert notifications in Defender for Cloud and configure security contacts.

```hcl
resource "azurerm_security_center_contact" "good_example" {
  email = "security@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact

