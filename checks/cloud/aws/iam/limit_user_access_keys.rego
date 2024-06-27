# METADATA
# title: No user should have more than one active access key.
# description: |
#   Multiple active access keys widens the scope for compromise.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AVD-AWS-0167
#   avd_id: AVD-AWS-0167
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: limit-user-access-keys
#   recommended_action: Limit the number of active access keys to one key per user.
#   frameworks:
#     cis-aws-1.4:
#       - "1.13"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0167

import rego.v1

deny contains res if {
	some user in input.aws.iam.users
	count([key | some key in user.accesskeys; key.active.value]) > 1
	res := result.new("User has more than one active access key", user)
}
