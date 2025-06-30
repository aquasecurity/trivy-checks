# METADATA
# title: Reduce unnecessary unauthorized access or information disclosure of S3 buckets.
# description: Unnecessary access to S3 buckets can lead to unauthorized access or information disclosure.
# scope: package
# related_resources:
#   - https://www.aquasec.com/blog/shadow-roles-aws-defaults-lead-to-service-takeover/
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0346
#   avd_id: AVD-AWS-0346
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: unauthorized-bucket-access
#   recommended_action: Allowing Get* along with Put* on all Resources can potentially allow unauthorized access and/or information disclosure from sensitive buckets.
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
