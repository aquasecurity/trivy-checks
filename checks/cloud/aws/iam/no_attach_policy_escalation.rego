# METADATA
# title: "IAM policy grants Attach*Policy with wildcard resource enabling privilege escalation"
# description: |
#   A principal with iam:AttachUserPolicy, iam:AttachRolePolicy, or iam:AttachGroupPolicy
#   and a wildcard resource can attach the AdministratorAccess managed policy to themselves
#   or any other identity. This enables immediate privilege escalation to full admin access.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0349
#   avd_id: AVD-AWS-0349
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Restrict iam:Attach*Policy to specific target ARNs using resource conditions. Never grant on Resource: *. Use SCPs to deny attaching admin-level policies."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0349

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

attach_actions := [
	"iam:AttachUserPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachGroupPolicy",
]

deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	target := attach_actions[_]
	is_dangerous_action(action, target)
	resource := statement.Resource[_]
	resource == "*"
	res := result.new(
		"IAM policy grants Attach*Policy with wildcard resource, enabling privilege escalation",
		policy,
	)
}
