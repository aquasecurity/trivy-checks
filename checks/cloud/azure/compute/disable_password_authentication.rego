# METADATA
# title: Password authentication should be disabled on Azure virtual machines
# description: |
#   Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0039
#   aliases:
#     - AVD-AZU-0039
#     - disable-password-authentication
#   long_id: azure-compute-disable-password-authentication
#   provider: azure
#   service: compute
#   severity: HIGH
#   recommended_action: Use ssh authentication for virtual machines
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   examples: checks/cloud/azure/compute/disable_password_authentication.yaml
package builtin.azure.compute.azure0039

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some vm in input.azure.compute.linuxvirtualmachines
	isManaged(vm)
	not vm.osprofilelinuxconfig.disablepasswordauthentication.value
	res := result.new(
		"Linux virtual machine allows password authentication.",
		metadata.obj_by_path(vm, ["osprofilelinuxconfig", "disablepasswordauthentication"]),
	)
}
