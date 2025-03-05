# METADATA
# title: IAM Password policy should have expiry less than or equal to 90 days.
# description: |
#   IAM account password policies should have a maximum age specified.
#
#   The account password policy should be set to expire passwords after 90 days or less.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AVD-AWS-0062
#   avd_id: AVD-AWS-0062
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: set-max-password-age
#   recommended_action: Limit the password duration with an expiry in the policy
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.11"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/set_max_password_age.yaml
package builtin.aws.iam.aws0062

import rego.v1

deny contains res if {
	policy := input.aws.iam.passwordpolicy
	isManaged(policy)
	policy.maxagedays.value > 90
	res := result.new("Password policy allows a maximum password age of greater than 90 days.", policy.maxagedays)
}
