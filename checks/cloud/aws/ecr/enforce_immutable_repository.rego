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
#   id: AVD-AWS-0031
#   avd_id: AVD-AWS-0031
#   provider: aws
#   service: ecr
#   severity: HIGH
#   short_code: enforce-immutable-repository
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
