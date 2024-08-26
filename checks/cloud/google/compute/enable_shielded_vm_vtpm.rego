# METADATA
# title: Instances should have Shielded VM VTPM enabled
# description: |
#   The virtual TPM provides numerous security measures to your VM.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext
# custom:
#   id: AVD-GCP-0041
#   avd_id: AVD-GCP-0041
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: enable-shielded-vm-vtpm
#   recommended_action: Enable Shielded VM VTPM
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm
#     good_examples: checks/cloud/google/compute/enable_shielded_vm_vtpm.tf.go
#     bad_examples: checks/cloud/google/compute/enable_shielded_vm_vtpm.tf.go
package builtin.google.compute.google0041

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.shieldedvm.vtpmenabled.value == false
	res := result.new(
		"Instance does not have VTPM for shielded VMs enabled.",
		instance.shieldedvm.vtpmenabled,
	)
}
