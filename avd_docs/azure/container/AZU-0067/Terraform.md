
Configure a disk encryption set ID for the AKS cluster to enable customer-managed key encryption.

```hcl
resource "azurerm_kubernetes_cluster" "good_example" {
  name                   = "example-aks"
  location               = azurerm_resource_group.example.location
  resource_group_name    = azurerm_resource_group.example.name
  dns_prefix             = "exampleaks"
  disk_encryption_set_id = azurerm_disk_encryption_set.example.id

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#disk_encryption_set_id

