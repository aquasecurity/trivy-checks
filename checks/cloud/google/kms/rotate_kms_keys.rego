# METADATA
# title: KMS keys should be rotated at least every 90 days
# description: |
#   Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0065
#   avd_id: AVD-GCP-0065
#   provider: google
#   service: kms
#   severity: HIGH
#   short_code: rotate-kms-keys
#   recommended_action: Set key rotation period to 90 days
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: kms
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period
#     good_examples: checks/cloud/google/kms/rotate_kms_keys.tf.go
#     bad_examples: checks/cloud/google/kms/rotate_kms_keys.tf.go
package builtin.google.kms.google0065

import rego.v1

deny contains res if {
	some ring in input.google.kms.keyrings
	some key in ring.keys
	key.rotationperiodseconds.value > 7776000
	res := result.new("Key has a rotation period of more than 90 days.", key.rotationperiodseconds)
}
