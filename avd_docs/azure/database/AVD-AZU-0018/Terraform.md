
Provide at least one email address for threat alerts

```hcl
resource "azurerm_mssql_server_security_alert_policy" "good_example" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  email_addresses = ["db-security@acme.org"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses

