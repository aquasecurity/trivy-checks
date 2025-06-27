# METADATA
# title: No plaintext password for compute instance
# description: |
#   Assigning a password to the compute instance using plaintext could lead to compromise; it would be preferable to use key-pairs as a login mechanism
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: OPNSTK-0001
#   aliases:
#     - AVD-OPNSTK-0001
#     - no-plaintext-password
#   long_id: openstack-compute-no-plaintext-password
#   provider: openstack
#   service: compute
#   severity: MEDIUM
#   recommended_action: Do not use plaintext passwords in terraform files
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: openstack
#   examples: checks/cloud/openstack/compute/no_plaintext_password.yaml
package builtin.openstack.compute.openstack0001

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some instance in input.openstack.compute.instances
	value.is_not_empty(instance.adminpassword)
	res := result.new("Instance has admin password set.", instance.adminpassword)
}
