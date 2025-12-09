
Update to a supported Python version (3.9 or higher). Consider migrating from azurerm_app_service to azurerm_linux_web_app for access to modern Python versions.

```hcl
# Supported Python version (3.9 or higher)
resource "azurerm_app_service" "good_example_supported" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    python_version = "3.9"
  }
}
```
```hcl
# Current stable version
resource "azurerm_app_service" "good_example_current" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    python_version = "3.12"
  }
}
```
```hcl
# No Python version specified - not using Python
resource "azurerm_app_service" "good_example_no_python" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    # No Python version specified - not using Python
  }
}
```
```hcl
# Modern Linux Web App with latest Python (recommended approach)
resource "azurerm_linux_web_app" "good_example_modern" {
  name                = "example-linux-webapp"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  service_plan_id     = azurerm_service_plan.example.id

  site_config {
    application_stack {
      python_version = "3.12"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_web_app#python_version

