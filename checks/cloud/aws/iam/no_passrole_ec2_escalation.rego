# METADATA
# title: "IAM policy grants iam:PassRole with ec2:RunInstances enabling privilege escalation"
# description: |
#   A principal with iam:PassRole and ec2:RunInstances can launch an EC2 instance with a
#   privileged instance profile attached. By accessing the instance metadata service (IMDS),
#   the attacker can steal the role credentials and escalate privileges.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pathfinding.cloud/
#   - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
# custom:
#   id: AWS-0350
#   avd_id: AVD-AWS-0350
#   provider: aws
#   service: iam
#   severity: HIGH
#   recommended_action: "Constrain iam:PassRole with iam:PassedToService condition key set to ec2.amazonaws.com. Limit role ARNs that can be passed using resource-level permissions on PassRole."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0350

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
	has_action(statements, "ec2:RunInstances")
	res := result.new(
		"IAM policy grants iam:PassRole + ec2:RunInstances, enabling privilege escalation via EC2 instance profile",
		policy,
	)
}
