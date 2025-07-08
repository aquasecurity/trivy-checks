# METADATA
# title: KMS keys should be rotated at least every 90 days
# description: |
#   Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0065
#   aliases:
#     - AVD-GCP-0065
#     - rotate-kms-keys
#   long_id: google-kms-rotate-kms-keys
#   provider: google
#   service: kms
#   severity: HIGH
#   recommended_action: Set key rotation period to 90 days
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: kms
#             provider: google
#   examples: checks/cloud/google/kms/rotate_kms_keys.yaml
package builtin.google.kms.google0065

import rego.v1

deny contains res if {
	some ring in input.google.kms.keyrings
	some key in ring.keys
	key.rotationperiodseconds.value > 7776000
	res := result.new("Key has a rotation period of more than 90 days.", key.rotationperiodseconds)
}
