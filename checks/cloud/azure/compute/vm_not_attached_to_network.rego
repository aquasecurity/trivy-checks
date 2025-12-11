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
#   id: AZU-0068
#   long_id: azure-compute-vm-not-attached-to-network
#   aliases:
#     - AVD-AZU-0068
#     - vm-not-attached-to-network
#     - azure-vm-not-attached-to-network
#   provider: azure
#   service: compute
#   severity: MEDIUM
#   recommended_action: Associate an NSG to the VM's NIC or subnet to control traffic.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   examples: checks/cloud/azure/compute/vm_not_attached_to_network.yaml
package builtin.azure.compute.azure0068

import rego.v1

no_security_groups(ni) if not ni.securitygroups

no_security_groups(ni) if count(ni.securitygroups) == 0

deny contains res if {
	vms := array.concat(
		object.get(input.azure.compute, "linuxvirtualmachines", []),
		object.get(input.azure.compute, "windowsvirtualmachines", []),
	)

	some vm in vms
	some nic in vm.virtualmachine.networkinterfaces
	no_security_groups(nic)
	res := result.new(
		"Virtual machine network interface is not associated with a network security group.",
		nic,
	)
}
