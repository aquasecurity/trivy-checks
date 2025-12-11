
Set FTPS state to 'FTPS Only' in App Service settings to prevent plaintext FTP.

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    ftps_state = "FtpsOnly"
  }
}
```
```hcl
resource "azurerm_app_service" "good_example_disabled" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    ftps_state = "Disabled"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#ftps_state

