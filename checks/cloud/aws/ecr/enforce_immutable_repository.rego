# METADATA
# title: ECR images tags shouldn't be mutable.
# description: |
#   ECR images should be set to IMMUTABLE to prevent code injection through image mutation.
#   This can be done by setting <code>image_tag_mutability</code> to <code>IMMUTABLE</code>
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://sysdig.com/blog/toctou-tag-mutability/
# custom:
#   id: AWS-0031
#   aliases:
#     - AVD-AWS-0031
#     - enforce-immutable-repository
#   long_id: aws-ecr-enforce-immutable-repository
#   provider: aws
#   service: ecr
#   severity: HIGH
#   recommended_action: Only use immutable images in ECR
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecr
#             provider: aws
#   examples: checks/cloud/aws/ecr/enforce_immutable_repository.yaml
package builtin.aws.ecr.aws0031

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some repo in input.aws.ecr.repositories
	not repo.imagetagsimmutable.value
	res := result.new(
		"Repository tags are mutable.",
		metadata.obj_by_path(repo, ["imagetagsimmutable"]),
	)
}
