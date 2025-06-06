
Enable logging for Queue Services

```hcl
resource "azurerm_storage_account" "good_example" {
  name                     = "example"
  resource_group_name      = data.azurerm_resource_group.example.name
  location                 = data.azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }
}

resource "azurerm_storage_queue" "good_example" {
  name                 = "my-queue"
  storage_account_name = azurerm_storage_account.good_example.name
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging

