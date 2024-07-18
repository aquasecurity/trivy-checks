# METADATA
# title: Password authentication should be disabled on Azure virtual machines
# description: |
#   Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0039
#   avd_id: AVD-AZU-0039
#   provider: azure
#   service: compute
#   severity: HIGH
#   short_code: disable-password-authentication
#   recommended_action: Use ssh authentication for virtual machines
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication
#     good_examples: checks/cloud/azure/compute/disable_password_authentication.tf.go
#     bad_examples: checks/cloud/azure/compute/disable_password_authentication.tf.go
package builtin.azure.compute.azure0039

import rego.v1

deny contains res if {
	some vm in input.azure.compute.linuxvirtualmachines
	isManaged(vm)
	not vm.osprofilelinuxconfig.disablepasswordauthentication.value
	res := result.new(
		"Linux virtual machine allows password authentication.",
		object.get(vm, ["osprofilelinuxconfig", "disablepasswordauthentication"], vm),
	)
}
