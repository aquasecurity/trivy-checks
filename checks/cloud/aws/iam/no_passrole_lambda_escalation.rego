# METADATA
# title: "IAM policy grants iam:PassRole with Lambda create and invoke enabling privilege escalation"
# description: |
#   A principal with iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction can create
#   a Lambda function with an administrative role attached, invoke it, and steal the role's
#   credentials. This combination of permissions enables a well-known privilege escalation path
#   through AWS Lambda.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0348
#   avd_id: AVD-AWS-0348
#   provider: aws
#   service: iam
#   severity: CRITICAL
#   recommended_action: "Separate iam:PassRole from Lambda creation/invocation permissions into different policies with different principals. Use iam:PassedToService condition key to restrict PassRole to lambda.amazonaws.com only."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0348

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

has_action(statements, target) if {
	statement := statements[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	is_dangerous_action(action, target)
}

deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	statements := doc.Statement
	has_action(statements, "iam:PassRole")
	has_action(statements, "lambda:CreateFunction")
	has_action(statements, "lambda:InvokeFunction")
	res := result.new(
		"IAM policy grants iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction, enabling privilege escalation via Lambda",
		policy,
	)
}
