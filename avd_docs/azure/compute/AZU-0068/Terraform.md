
Associate an NSG to the VM's NIC or subnet to control traffic.

```hcl
resource "azurerm_network_security_group" "example" {
  name                = "vm-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_network_interface" "good_example" {
  name                      = "vm-nic"
  location                  = azurerm_resource_group.example.location
  resource_group_name       = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "good_example" {
  name                = "good-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"

  network_interface_ids = [
    azurerm_network_interface.good_example.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}
```
```hcl
resource "azurerm_network_security_group" "example" {
  name                = "vm-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_network_interface" "good_example" {
  name                      = "vm-nic"
  location                  = azurerm_resource_group.example.location
  resource_group_name       = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "good_example" {
  name                = "good-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "P@$$w0rd1234!"

  network_interface_ids = [
    azurerm_network_interface.good_example.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#network_interface_ids

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine#network_interface_ids

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#network_interface_ids

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface#network_security_group_id

