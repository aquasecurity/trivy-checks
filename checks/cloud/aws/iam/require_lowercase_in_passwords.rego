# METADATA
# title: IAM Password policy should have requirement for at least one lowercase character.
# description: |
#   IAM account password policies should ensure that passwords content including at least one lowercase character.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AWS-0058
#   aliases:
#     - AVD-AWS-0058
#     - require-lowercase-in-passwords
#   long_id: aws-iam-require-lowercase-in-passwords
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   recommended_action: Enforce longer, more complex passwords in the policy
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.6"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/require_lowercase_in_passwords.yaml
package builtin.aws.iam.aws0058

import rego.v1

deny contains res if {
	policy := input.aws.iam.passwordpolicy
	isManaged(policy)
	not policy.requirelowercase.value

	res := result.new("Password policy does not require lowercase characters", policy.requirelowercase)
}
