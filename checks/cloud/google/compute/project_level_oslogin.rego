# METADATA
# title: OS Login should be enabled at project level
# description: |
#   OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0042
#   avd_id: AVD-GCP-0042
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: project-level-oslogin
#   recommended_action: Enable OS Login at project level
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/project_level_oslogin.yaml
package builtin.google.compute.google0042

import rego.v1

deny contains res if {
	metadata := input.google.compute.projectmetadata
	isManaged(metadata)
	not metadata.enableoslogin.value
	res := result.new("OS Login is disabled at project level.", metadata)
}
