
Use ssh authentication for virtual machines

```hcl
resource "azurerm_linux_virtual_machine" "good_linux_example" {
  name                = "good-linux-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "somePassword"

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
}
```
```hcl
resource "azurerm_virtual_machine" "good_example" {
  name                = "good-linux-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"


  os_profile_linux_config {
    ssh_keys = [{
      key_data = file("~/.ssh/id_rsa.pub")
      path     = "~/.ssh/id_rsa.pub"
    }]

    disable_password_authentication = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication

