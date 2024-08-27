# METADATA
# title: IAM Users should have MFA enforcement activated.
# description: |
#   IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AVD-AWS-0145
#   avd_id: AVD-AWS-0145
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: enforce-user-mfa
#   recommended_action: Enable MFA for the user account
#   frameworks:
#     cis-aws-1.2:
#       - "1.2"
#     cis-aws-1.4:
#       - "1.4"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0145

import rego.v1

import data.lib.aws.iam

deny contains res if {
	some user in input.aws.iam.users
	not iam.user_has_mfa_devices(user)
	iam.is_user_logged_in(user)
	res := result.new("User account does not have MFA", user)
}
