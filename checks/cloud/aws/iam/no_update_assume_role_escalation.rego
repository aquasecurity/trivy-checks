# METADATA
# title: "IAM policy grants iam:UpdateAssumeRolePolicy with wildcard resource enabling privilege escalation"
# description: |
#   A principal with iam:UpdateAssumeRolePolicy and a wildcard resource can rewrite the trust
#   policy of any IAM role to allow self-assumption. This enables lateral movement to any role
#   in the account, including administrative roles, effectively granting full account compromise.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0352
#   avd_id: AVD-AWS-0352
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Restrict iam:UpdateAssumeRolePolicy to specific role ARNs. This permission should only be held by identity management automation, never human users or application roles."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0352

import rego.v1

is_dangerous_action(action, target) if {
	lower(action) == lower(target)
}

is_dangerous_action(action, target) if {
	service := split(target, ":")[0]
	lower(action) == concat(":", [lower(service), "*"])
}

is_dangerous_action(action, _) if {
	action == "*"
}

deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	is_dangerous_action(action, "iam:UpdateAssumeRolePolicy")
	resource := statement.Resource[_]
	resource == "*"
	res := result.new(
		"IAM policy grants iam:UpdateAssumeRolePolicy with wildcard resource, enabling privilege escalation via trust policy hijacking",
		policy,
	)
}
