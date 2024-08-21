# METADATA
# title: IAM Password policy should have requirement for at least one uppercase character.
# description: |
#   ,
#
#   IAM account password policies should ensure that passwords content including at least one uppercase character.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AVD-AWS-0061
#   avd_id: AVD-AWS-0061
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: require-uppercase-in-passwords
#   recommended_action: Enforce longer, more complex passwords in the policy
#   frameworks:
#     cis-aws-1.2:
#       - "1.5"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy
#     good_examples: checks/cloud/aws/iam/require_uppercase_in_passwords.tf.go
#     bad_examples: checks/cloud/aws/iam/require_uppercase_in_passwords.tf.go
package builtin.aws.iam.aws0061

import rego.v1

deny contains res if {
	policy := input.aws.iam.passwordpolicy
	isManaged(policy)
	not policy.requireuppercase.value

	res := result.new("Password policy does not require uppercase characters.", policy.requireuppercase)
}