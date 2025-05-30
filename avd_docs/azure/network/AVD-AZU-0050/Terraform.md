
Block port 22 access from the internet

```hcl
resource "azurerm_network_security_rule" "good_example" {
  name                       = "good_example_security_rule"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "TCP"
  source_port_range          = "*"
  destination_port_range     = "22"
  source_address_prefix      = "82.102.23.23" # specific address
  destination_address_prefix = "*"
}
```
```hcl
resource "azurerm_network_security_rule" "good_example" {
  name                       = "good_example_security_rule"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "ICMP" # icmp
  source_port_range          = "*"
  destination_port_range     = "22"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
}
```
```hcl
resource "azurerm_network_security_rule" "good_example" {
  name                       = "good_example_security_rule"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "TCP"
  source_port_range          = "*"
  destination_port_range     = "8080" # not ssh
  source_address_prefix      = "*"
  destination_address_prefix = "*"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges

