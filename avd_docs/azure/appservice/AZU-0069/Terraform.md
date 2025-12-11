
Update to a supported PHP version (8.1 or higher). Consider migrating from azurerm_app_service to azurerm_linux_web_app for access to modern PHP versions.

```hcl
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    php_version = "8.2"
  }
}
```
```hcl
resource "azurerm_app_service" "good_example_no_php" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    # No PHP version specified - not using PHP
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#php_version

