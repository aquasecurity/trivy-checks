# METADATA
# title: Instances should have Shielded VM integrity monitoring enabled
# description: |
#   Integrity monitoring helps you understand and make decisions about the state of your VM instances.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring
# custom:
#   id: AVD-GCP-0045
#   avd_id: AVD-GCP-0045
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: enable-shielded-vm-im
#   recommended_action: Enable Shielded VM Integrity Monitoring
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm
#     good_examples: checks/cloud/google/compute/enable_shielded_vm_im.yaml
#     bad_examples: checks/cloud/google/compute/enable_shielded_vm_im.yaml
package builtin.google.compute.google0045

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.shieldedvm.integritymonitoringenabled.value == false
	res := result.new("Instance does not have shielded VM integrity monitoring enabled.", instance.shieldedvm.integritymonitoringenabled)
}
