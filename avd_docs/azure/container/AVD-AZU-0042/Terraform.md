
Enable RBAC

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  // azurerm < 2.99.0
  role_based_access_control {
    enabled = true
  }
}
```
```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  // azurerm >= 2.99.0
  role_based_access_control_enabled = true
}
```
```hcl
resource "azurerm_kubernetes_cluster" "aks_cluster" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  default_node_pool {
    name    = "default"
    vm_size = "Standard_D2_v2"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = [data.azuread_group.aks_admins.object_id]
  }
}
```

#### Remediation Links
 - https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control

