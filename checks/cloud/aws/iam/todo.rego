# METADATA
# title: todo
# description: todo
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0346
#   avd_id: AVD-AWS-0346
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: todo
#   recommended_action: Create more restrictive S3 policies
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0346

import rego.v1

is_action_allowed(statement, action_to_check) if {
	lower(statement.Effect) == "allow"
	some action in statement.Action
	lower(action) == lower(action_to_check)
}

allows_s3_put_and_get(document) if {
	value := json.unmarshal(document)
	some statement in value.Statement
	lower(statement.Effect) == "allow"
	statement.Resource == "*"
	allowed_actions := [lower(action) | some action in statement.Action]
	"s3:get*" in allowed_actions
	"s3:put*" in allowed_actions
}

deny contains res if {
	some policy in input.aws.iam.policies
	allows_s3_put_and_get(policy.document.value)
	res = result.new(
		"IAM policy allows both 's3:Get*' and 's3:Put*' actions on all resources",
		policy.document,
	)
}

deny contains res if {
	some role in input.aws.iam.roles
	some policy in role.policies
	allows_s3_put_and_get(policy.document.value)
	res = result.new(
		"IAM role policy allows both 's3:Get*' and 's3:Put*' actions on all resources",
		policy.document,
	)
}
