# METADATA
# title: Disable project-wide SSH keys for all instances
# description: |
#   Use of project-wide SSH keys means that a compromise of any one of these key pairs can result in all instances being compromised. It is recommended to use instance-level keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0030
#   avd_id: AVD-GCP-0030
#   provider: google
#   service: compute
#   severity: MEDIUM
#   short_code: no-project-wide-ssh-keys
#   recommended_action: Disable project-wide SSH keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_project_wide_ssh_keys.yaml
package builtin.google.compute.google0030

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	instance.enableprojectsshkeyblocking.value == false
	res := result.new("Instance allows use of project-level SSH keys.", instance.enableprojectsshkeyblocking)
}
