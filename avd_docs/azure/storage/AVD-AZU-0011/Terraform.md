
Use a more recent TLS version for the storage account

```hcl
# provider version > 5.0
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  min_tls_version     = "TLS1_3"
}
```
```hcl
# provider version < 5.0
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  min_tls_version     = "TLS1_2"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version

