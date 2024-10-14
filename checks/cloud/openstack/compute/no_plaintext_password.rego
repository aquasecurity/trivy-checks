# METADATA
# title: No plaintext password for compute instance
# description: |
#   Assigning a password to the compute instance using plaintext could lead to compromise; it would be preferable to use key-pairs as a login mechanism
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-OPNSTK-0001
#   avd_id: AVD-OPNSTK-0001
#   provider: openstack
#   service: compute
#   severity: MEDIUM
#   short_code: no-plaintext-password
#   recommended_action: Do not use plaintext passwords in terraform files
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: openstack
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/compute_instance_v2#admin_pass
#     good_examples: checks/cloud/openstack/compute/no_plaintext_password.yaml
#     bad_examples: checks/cloud/openstack/compute/no_plaintext_password.yaml
package builtin.openstack.compute.openstack0001

import rego.v1

deny contains res if {
	some instance in input.openstack.compute.instances
	instance.adminpassword.value != ""
	res := result.new("Instance has admin password set.", instance.adminpassword)
}
