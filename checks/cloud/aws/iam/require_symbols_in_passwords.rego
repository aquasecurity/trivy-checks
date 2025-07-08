# METADATA
# title: IAM Password policy should have requirement for at least one symbol in the password.
# description: |
#   IAM account password policies should ensure that passwords content including a symbol.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AWS-0060
#   aliases:
#     - AVD-AWS-0060
#     - require-symbols-in-passwords
#   long_id: aws-iam-require-symbols-in-passwords
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   recommended_action: Enforce longer, more complex passwords in the policy
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.7"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/require_symbols_in_passwords.yaml
package builtin.aws.iam.aws0060

import rego.v1

deny contains res if {
	policy := input.aws.iam.passwordpolicy
	isManaged(policy)
	not policy.requiresymbols.value

	res := result.new("Password policy does not require symbols.", policy.requiresymbols)
}
