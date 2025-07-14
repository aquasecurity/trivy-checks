# METADATA
# title: "IAM Pass Role Filtering"
# description: "Ensures any IAM pass role attached to roles are flagged and warned."
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
# custom:
#   id: AWS-0342
#   aliases:
#     - AVD-AWS-0342
#     - filter-passrole-access
#   long_id: aws-iam-filter-passrole-access
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   recommended_action: "Resolve permission escalations by denying pass role'"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0342

import rego.v1

allows_permission(statements, permission, effect) if {
	statement := statements[_]
	statement.Effect == effect
	action = statement.Action[_]
	action == permission
}

deny contains res if {
	policy := input.aws.iam.policies[_]
	value = json.unmarshal(policy.document.value)
	statements = value.Statement
	not allows_permission(statements, "iam:PassRole", "Deny")
	allows_permission(statements, "iam:PassRole", "Allow")
	res = result.new("IAM policy allows 'iam:PassRole' action", policy.document)
}
