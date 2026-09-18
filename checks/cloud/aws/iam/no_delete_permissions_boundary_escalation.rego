# METADATA
# title: "IAM policy grants Delete*PermissionsBoundary enabling privilege escalation"
# description: |
#   A principal with iam:DeleteUserPermissionsBoundary or iam:DeleteRolePermissionsBoundary
#   can remove permissions boundaries that act as guardrails on IAM identities. Once boundaries
#   are removed, the identity's full unconstrained permissions become active, which may include
#   administrative access that was previously limited by the boundary.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0353
#   avd_id: AVD-AWS-0353
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   recommended_action: "Restrict boundary-deletion permissions to a dedicated security automation role. Add SCP deny rules preventing boundary removal except by break-glass principals."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0353

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

boundary_actions := [
	"iam:DeleteUserPermissionsBoundary",
	"iam:DeleteRolePermissionsBoundary",
]

deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	target := boundary_actions[_]
	is_dangerous_action(action, target)
	res := result.new(
		"IAM policy grants Delete*PermissionsBoundary, enabling privilege escalation by removing guardrails",
		policy,
	)
}
