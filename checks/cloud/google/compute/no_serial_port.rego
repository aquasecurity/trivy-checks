# METADATA
# title: Disable serial port connectivity for all instances
# description: |
#   When serial port access is enabled, the access is not governed by network security rules meaning the port can be exposed publicly.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0032
#   aliases:
#     - AVD-GCP-0032
#     - no-serial-port
#   long_id: google-compute-no-serial-port
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: Disable serial port access
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_serial_port.yaml
package builtin.google.compute.google0032

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.enableserialport.value == true
	res := result.new("Instance has serial port enabled.", instance.enableserialport)
}
