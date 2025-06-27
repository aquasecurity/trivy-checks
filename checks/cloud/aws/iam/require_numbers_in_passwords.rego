# METADATA
# title: IAM Password policy should have requirement for at least one number in the password.
# description: |
#   IAM account password policies should ensure that passwords content including at least one number.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AWS-0059
#   aliases:
#     - AVD-AWS-0059
#     - require-numbers-in-passwords
#   long_id: aws-iam-require-numbers-in-passwords
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   recommended_action: Enforce longer, more complex passwords in the policy
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.8"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/require_numbers_in_passwords.yaml
package builtin.aws.iam.aws0059

import rego.v1

deny contains res if {
	policy := input.aws.iam.passwordpolicy
	isManaged(policy)
	not policy.requirenumbers.value

	res := result.new("Password policy does not require numbers.", policy.requirenumbers)
}
