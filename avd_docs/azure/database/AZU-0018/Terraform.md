
Provide at least one email address for threat alerts

```hcl
resource "azurerm_sql_server" "example" {
  name                = "mysqlserver"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  version             = "12.0"
}

resource "azurerm_mssql_server_security_alert_policy" "good_example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  state               = "Enabled"

  email_addresses = ["db-security@acme.org"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_addresses

