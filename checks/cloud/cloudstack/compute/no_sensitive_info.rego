# METADATA
# title: No sensitive data stored in user_data
# description: |
#   When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: CLDSTK-0001
#   aliases:
#     - AVD-CLDSTK-0001
#     - no-sensitive-info
#   long_id: cloudstack-compute-no-sensitive-info
#   provider: cloudstack
#   service: compute
#   severity: HIGH
#   recommended_action: Don't use sensitive data in the user data section
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: cloudstack
#   examples: checks/cloud/cloudstack/compute/no_sensitive_info.yaml
package builtin.cloudstack.compute.cloudstack0001

import rego.v1

deny contains res if {
	some instance in input.cloudstack.compute.instances
	isManaged(instance)
	scan_result := squealer.scan_string(instance.userdata.value)
	scan_result.transgressionFound
	res := result.new("Instance user data contains secret(s).", instance.userdata)
}
