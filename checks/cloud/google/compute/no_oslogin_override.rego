# METADATA
# title: Instances should not override the project setting for OS Login
# description: |
#   OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   aliases:
#     - google-compute-no-oslogin-override
#   avd_id: AVD-GCP-0036
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: no-oslogin-override
#   recommended_action: Enable OS Login at project level and remove instance-level overrides
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_oslogin_override.yaml
package builtin.google.compute.google0036

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.osloginenabled.value == false
	res := result.new("Instance has OS Login disabled.", instance.osloginenabled)
}
