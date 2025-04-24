# METADATA
# title: "Disallow unrestricted S3 IAM Policies"
# description: "Ensure that the creation of the unrestricted S3 IAM policies is disallowed."
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0345
#   avd_id: AVD-AWS-0345
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: no-s3-full-access
#   recommended_action: "Create more restrictive S3 policies"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
#   examples: checks/cloud/aws/iam/limit_s3_full_access.yaml
package builtin.aws.iam.aws0345

import rego.v1

allows_permission(statements, permission, effect) if {
	statement := statements[_]
	statement.Effect == effect
	action = statement.Action[_]
	action == permission
}

is_s3_full_access_allowed(document) if {
	value := json.unmarshal(document)
	statements := value.Statement

	some perm_deny in {"s3:*", "s3:get*", "s3:put*", "s3:delete*", "s3:list*"}
	not allows_permission(statements, perm_deny, "Deny")

	some perm_allow in {"s3:*", "s3:get*", "s3:put*", "s3:delete*", "s3:list*"}
	allows_permission(statements, perm_allow, "Allow")
}

deny contains res if {
	policy := input.aws.iam.policies[_]
	value = is_s3_full_access_allowed(policy.document.value)
	res = result.new("IAM policy allows 's3:*' action", policy.document)
}

deny contains res if {
	role := input.aws.iam.roles[_]
	policy := role.policies[_]
	value = is_s3_full_access_allowed(policy.document.value)
	res = result.new("IAM role uses a policy that allows 's3:*' action", role)
}
