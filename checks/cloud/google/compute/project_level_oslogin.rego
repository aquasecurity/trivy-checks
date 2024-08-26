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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#
#     good_examples: checks/cloud/google/compute/project_level_oslogin.tf.go
#     bad_examples: checks/cloud/google/compute/project_level_oslogin.tf.go
package builtin.google.compute.google0042

import rego.v1

deny contains res if {
	metadata := input.google.compute.projectmetadata
	isManaged(metadata)
	not metadata.enableoslogin.value
	res := result.new("OS Login is disabled at project level.", metadata)
}
