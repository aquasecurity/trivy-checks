# METADATA
# title: VM Not Attached To Network
# description: |
#   VMs without NSGs are exposed without traffic control or inspection.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#network_interface_ids
# custom:
#   id: AVD-AZU-0068
#   avd_id: AVD-AZU-0068
#   aliases:
#     - azure-vm-not-attached-to-network
#   provider: azure
#   service: compute
#   severity: MEDIUM
#   short_code: vm-not-attached-to-network
#   recommended_action: Associate an NSG to the VM's NIC or subnet to control traffic.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   examples: checks/cloud/azure/compute/vm_not_attached_to_network.yaml
package builtin.azure.compute.azure0068

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	vms := array.concat(
		object.get(input.azure.compute, "linuxvirtualmachines", []),
		object.get(input.azure.compute, "windowsvirtualmachines", []),
	)

	some vm in vms
	isManaged(vm)
	some nic in vm.virtualmachine.networkinterfaces
	count(nic.securitygroups) == 0
	res := result.new(
		"Virtual machine network interface is not associated with a network security group.",
		nic,
	)
}
