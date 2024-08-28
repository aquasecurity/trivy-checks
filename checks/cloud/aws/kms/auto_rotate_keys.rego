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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation
#     good_examples: checks/cloud/aws/kms/auto_rotate_keys.tf.go
#     bad_examples: checks/cloud/aws/kms/auto_rotate_keys.tf.go
package builtin.aws.kms.aws0065

import rego.v1

deny contains res if {
	some key in input.aws.kms.keys
	key.usage.value != "SIGN_VERIFY"
	key.rotationenabled.value == false
	res := result.new("Key does not have rotation enabled.", key.rotationenabled)
}
