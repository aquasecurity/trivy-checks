# METADATA
# title: ECR repository has image scans disabled.
# description: |
#   Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
# custom:
#   id: AVD-AWS-0030
#   avd_id: AVD-AWS-0030
#   provider: aws
#   service: ecr
#   severity: HIGH
#   short_code: enable-image-scans
#   recommended_action: Enable ECR image scanning
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecr
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration
#     good_examples: checks/cloud/aws/ecr/enable_image_scans.yaml
#     bad_examples: checks/cloud/aws/ecr/enable_image_scans.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/ecr/enable_image_scans.yaml
#     bad_examples: checks/cloud/aws/ecr/enable_image_scans.yaml
package builtin.aws.ecr.aws0030

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some repo in input.aws.ecr.repositories
	not repo.imagescanning.scanonpush.value
	res := result.new(
		"Image scanning is not enabled",
		metadata.obj_by_path(repo, ["imagescanning", "scanonpush"]),
	)
}
