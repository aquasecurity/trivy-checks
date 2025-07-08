# METADATA
# title: Instances should have Shielded VM secure boot enabled
# description: |
#   Secure boot helps ensure that the system only runs authentic software.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/security/shielded-cloud/shielded-vm#secure-boot
# custom:
#   id: GCP-0067
#   aliases:
#     - AVD-GCP-0067
#     - enable-shielded-vm-sb
#   long_id: google-compute-enable-shielded-vm-sb
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: Enable Shielded VM secure boot
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/enable_shielded_vm_sb.yaml
package builtin.google.compute.google0067

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.shieldedvm.securebootenabled.value == false
	res := result.new(
		"Instance does not have shielded VM secure boot enabled.",
		instance.shieldedvm.securebootenabled,
	)
}
