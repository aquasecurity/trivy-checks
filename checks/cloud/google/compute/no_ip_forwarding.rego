# METADATA
# title: Instances should not have IP forwarding enabled
# description: |
#   Disabling IP forwarding ensures the instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0043
#   aliases:
#     - AVD-GCP-0043
#     - no-ip-forwarding
#   long_id: google-compute-no-ip-forwarding
#   provider: google
#   service: compute
#   severity: HIGH
#   recommended_action: Disable IP forwarding
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_ip_forwarding.yaml
package builtin.google.compute.google0043

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.canipforward.value == true
	res := result.new("Instance has IP forwarding allowed", instance.canipforward)
}
