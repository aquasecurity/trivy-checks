# METADATA
# title: Force destroy is enabled on Spaces bucket which is dangerous
# description: |
#   Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   aliases:
#     - digitalocean-spaces-disable-force-destroy
#   avd_id: AVD-DIG-0009
#   provider: digitalocean
#   service: spaces
#   severity: MEDIUM
#   short_code: disable-force-destroy
#   recommended_action: Don't use force destroy on bucket configuration
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: spaces
#             provider: digitalocean
#   examples: checks/cloud/digitalocean/spaces/disable_force_destroy.yaml
package builtin.digitalocean.spaces.digitalocean0009

import rego.v1

deny contains res if {
	some bucket in input.digitalocean.spaces.buckets
	bucket.forcedestroy.value == true
	res := result.new("Bucket has force-destroy enabled.", bucket.forcedestroy)
}
