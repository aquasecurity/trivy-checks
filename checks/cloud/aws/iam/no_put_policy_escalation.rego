# METADATA
# title: "IAM policy grants Put*Policy with wildcard resource enabling privilege escalation"
# description: |
#   A principal with iam:PutUserPolicy, iam:PutRolePolicy, or iam:PutGroupPolicy and a wildcard
#   resource can write an inline policy with admin permissions on any IAM identity, including
#   themselves. This enables immediate privilege escalation to full administrative access.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0351
#   avd_id: AVD-AWS-0351
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Never grant iam:Put*Policy with unrestricted resources. Use permissions boundaries on all principals. Implement SCPs limiting inline policy creation."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0351

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

put_actions := [
	"iam:PutUserPolicy",
	"iam:PutRolePolicy",
	"iam:PutGroupPolicy",
]

deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	target := put_actions[_]
	is_dangerous_action(action, target)
	resource := statement.Resource[_]
	resource == "*"
	res := result.new(
		"IAM policy grants Put*Policy with wildcard resource, enabling privilege escalation",
		policy,
	)
}
