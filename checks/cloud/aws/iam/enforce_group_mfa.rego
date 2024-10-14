# METADATA
# title: IAM groups should have MFA enforcement activated.
# description: |
#   IAM groups should be protected with multi factor authentication to add safe guards to password compromise.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
# custom:
#   id: AVD-AWS-0123
#   avd_id: AVD-AWS-0123
#   aliases:
#     - aws-iam-enforce-mfa
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: enforce-group-mfa
#   recommended_action: Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest
#       - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
#     good_examples: checks/cloud/aws/iam/enforce_group_mfa.yaml
#     bad_examples: checks/cloud/aws/iam/enforce_group_mfa.yaml
package builtin.aws.iam.aws0123

import rego.v1

deny contains res if {
	some group in input.aws.iam.groups
	not is_group_mfa_enforced(group)
	res := result.new("Multi-Factor authentication is not enforced for group", group)
}

is_group_mfa_enforced(group) if {
	some policy in group.policies
	value := json.unmarshal(policy.document.value)
	some condition in value.Statement[_].Condition
	some key, _ in condition
	key == "aws:MultiFactorAuthPresent"
}
