# METADATA
# title: "IAM policy grants iam:CreatePolicyVersion permission enabling privilege escalation"
# description: |
#   A principal with iam:CreatePolicyVersion can create a new version of an IAM policy with
#   unrestricted permissions (e.g., *:*) and set it as the default version. This effectively
#   grants the principal full administrative access, bypassing the original policy restrictions.
#   This is a well-known privilege escalation vector in AWS environments.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0347
#   avd_id: AVD-AWS-0347
#   provider: aws
#   service: iam
#   severity: CRITICAL
#   recommended_action: "Remove iam:CreatePolicyVersion from IAM policies unless strictly required for infrastructure automation. Use permissions boundaries to limit policy modification scope."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0347

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
	is_dangerous_action(action, "iam:CreatePolicyVersion")
	resource := statement.Resource[_]
	resource == "*"
	res := result.new(
		"IAM policy grants iam:CreatePolicyVersion with wildcard resource, enabling privilege escalation",
		policy,
	)
}
