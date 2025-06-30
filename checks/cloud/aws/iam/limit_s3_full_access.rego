# METADATA
# title: "Disallow unrestricted S3 IAM Policies"
# description: "Ensure that the creation of the unrestricted S3 IAM policies is disallowed."
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0345
#   avd_id: AVD-AWS-0345
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: no-s3-full-access
#   recommended_action: "Create more restrictive S3 policies"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
#   examples: checks/cloud/aws/iam/limit_s3_full_access.yaml
package builtin.aws.iam.aws0345

import rego.v1

dangerous_actions := {"s3:*"}

is_action_allowed(statements, action_to_check) := action if {
	some statement in statements
	lower(statement.Effect) == "allow"
	some action in statement.Action
	lower(action) == lower(action_to_check)
}

is_overridden_by_deny(statements, action_to_check) if {
	some statement in statements
	lower(statement.Effect) == "deny"
	some action in statement.Action
	lower(action) == lower(action_to_check)
}

allowed_s3_dangerous_actions(document) := [action |
	value := json.unmarshal(document)
	some action_to_check in dangerous_actions
	not is_overridden_by_deny(value.Statement, action_to_check)
	action := is_action_allowed(value.Statement, action_to_check)
]

deny contains res if {
	some policy in input.aws.iam.policies
	some action in allowed_s3_dangerous_actions(policy.document.value)
	res = result.new(
		sprintf("IAM policy allows '%s' action", [action]),
		policy.document,
	)
}

deny contains res if {
	some role in input.aws.iam.roles
	some policy in role.policies
	some action in allowed_s3_dangerous_actions(policy.document.value)
	res = result.new(
		sprintf("IAM role uses a policy that allows '%s' action", [action]),
		policy.document,
	)
}
