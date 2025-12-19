
Enable secure transfer and set minimum TLS version to TLS1_2

```hcl
resource "azurerm_storage_account" "good_example" {
  name                       = "storageaccountname"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
}
```
```hcl
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#https_traffic_only_enabled

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version

