# METADATA
# title: Disable serial port connectivity for all instances
# description: |
#   When serial port access is enabled, the access is not governed by network security rules meaning the port can be exposed publicly.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0032
#   avd_id: AVD-GCP-0032
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: no-serial-port
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
