# METADATA
# title: Spaces buckets should have versioning enabled
# description: |
#   Versioning is a means of keeping multiple variants of an object in the same bucket. You can use the Spaces (S3) Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. With versioning you can recover more easily from both unintended user actions and application failures.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
# custom:
#   id: AVD-DIG-0007
#   avd_id: AVD-DIG-0007
#   provider: digitalocean
#   service: spaces
#   severity: MEDIUM
#   short_code: versioning-enabled
#   recommended_action: Enable versioning to protect against accidental or malicious removal or modification
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: spaces
#             provider: digitalocean
#   examples: checks/cloud/digitalocean/spaces/versioning_enabled.yaml
package builtin.digitalocean.spaces.digitalocean0007

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some bucket in input.digitalocean.spaces.buckets
	versioning_disabled(bucket)
	res := result.new(
		"Bucket does not have versioning enabled.",
		metadata.obj_by_path(bucket, ["versioning", "enabled"]),
	)
}

versioning_disabled(bucket) if value.is_false(bucket.versioning.enabled)

versioning_disabled(bucket) if not bucket.versioning.enabled
