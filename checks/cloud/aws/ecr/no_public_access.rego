# METADATA
# title: ECR repository policy must block public access
# description: |
#   Allowing public access to the ECR repository risks leaking sensitive of abusable information
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html
# custom:
#   id: AVD-AWS-0032
#   avd_id: AVD-AWS-0032
#   provider: aws
#   service: ecr
#   severity: HIGH
#   short_code: no-public-access
#   recommended_action: Do not allow public access in the policy
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecr
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy#policy
#     good_examples: checks/cloud/aws/ecr/no_public_access.tf.go
#     bad_examples: checks/cloud/aws/ecr/no_public_access.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ecr/no_public_access.cf.go
#     bad_examples: checks/cloud/aws/ecr/no_public_access.cf.go
package builtin.aws.ecr.aws0032

import rego.v1

deny contains res if {
	some repo in input.aws.ecr.repositories
	some policy in repo.policies
	value := json.unmarshal(policy.document.value)
	some statement in value.Statement
	has_ecr_action(statement)
	has_public_access(statement)
	res := result.new("Policy provides public access to the ECR repository.", policy.document)
}

has_ecr_action(statement) if {
	some action in statement.Action
	startswith(action, "ecr:")
}

has_public_access(statement) if {
	statement.Principal == "*"
}

has_public_access(statement) if {
	"*" in statement.Principal.AWS
}
