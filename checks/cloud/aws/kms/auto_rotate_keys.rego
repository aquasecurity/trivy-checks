# METADATA
# title: A KMS key is not configured to auto-rotate.
# description: |
#   You should configure your KMS keys to auto rotate to maintain security and defend against compromise.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
# custom:
#   id: AVD-AWS-0065
#   avd_id: AVD-AWS-0065
#   provider: aws
#   service: kms
#   severity: MEDIUM
#   short_code: auto-rotate-keys
#   recommended_action: Configure KMS key to auto rotate
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: kms
#             provider: aws
#   examples: checks/cloud/aws/kms/auto_rotate_keys.yaml
package builtin.aws.kms.aws0065

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some key in input.aws.kms.keys
	is_not_sign_key(key)
	rotation_disabled(key)
	res := result.new(
		"Key does not have rotation enabled.",
		metadata.obj_by_path(key, ["rotationenabled"]),
	)
}

is_not_sign_key(key) if value.is_not_equal(key.usage, "SIGN_VERIFY")

is_not_sign_key(key) if not key.usage

rotation_disabled(key) if value.is_false(key.rotationenabled)

rotation_disabled(key) if not key.rotationenabled
