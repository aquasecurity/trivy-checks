
Set retention periods of database auditing to greater than 90 days

```hcl
resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
}

resource "azurerm_mssql_database_extended_auditing_policy" "good_example" {
  database_id                             = azurerm_mssql_database.example.id
  storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.example.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days

