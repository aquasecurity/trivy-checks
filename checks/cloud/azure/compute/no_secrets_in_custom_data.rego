# METADATA
# title: Ensure that no sensitive credentials are exposed in VM custom_data
# description: |
#   When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0037
#   avd_id: AVD-AZU-0037
#   provider: azure
#   service: compute
#   severity: MEDIUM
#   short_code: no-secrets-in-custom-data
#   recommended_action: Don't use sensitive credentials in the VM custom_data
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data
#     good_examples: checks/cloud/azure/compute/no_secrets_in_custom_data.tf.go
#     bad_examples: checks/cloud/azure/compute/no_secrets_in_custom_data.tf.go
package builtin.azure.compute.azure0037

import rego.v1

deny contains res if {
	vms := array.concat(
		object.get(input.azure.compute, "linuxvirtualmachines", []),
		object.get(input.azure.compute, "windowsvirtualmachines", []),
	)

	some vm in vms
	scan_result := squealer.scan_string(vm.virtualmachine.customdata.value)
	scan_result.transgressionFound
	res := result.new(
		"Virtual machine includes secret(s) in custom data.",
		vm.virtualmachine,
	)
}
