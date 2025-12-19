# METADATA
# title: Instances should not override the project setting for OS Login
# description: |
#   OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0036
#   long_id: google-compute-no-oslogin-override
#   aliases:
#     - AVD-GCP-0036
#     - no-oslogin-override
#   provider: google
#   service: compute
#   severity: MEDIUM
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

import data.lib.cloud.value

deny contains res if {
	some instance in input.google.compute.instances
	os_login_disabled(instance)
	res := result.new("Instance has OS Login disabled.", instance.osloginenabled)
}

os_login_disabled(instance) if not instance.osloginenabled
os_login_disabled(instance) if value.is_false(instance.osloginenabled)
