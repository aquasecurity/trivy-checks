# METADATA
# title: Ensure that lambda function permission has a source arn specified
# description: |
#   When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to.
#   Without this, any resource from principal will be granted permission – even if that resource is from another account.
#   For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html
# custom:
#   id: AVD-AWS-0067
#   avd_id: AVD-AWS-0067
#   provider: aws
#   service: lambda
#   severity: CRITICAL
#   short_code: restrict-source-arn
#   recommended_action: Always provide a source arn for Lambda permissions
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: lambda
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission
#     good_examples: checks/cloud/aws/lambda/restrict_source_arn.yaml
#     bad_examples: checks/cloud/aws/lambda/restrict_source_arn.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/lambda/restrict_source_arn.yaml
#     bad_examples: checks/cloud/aws/lambda/restrict_source_arn.yaml
package builtin.aws.lambda.aws0067

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some func in input.aws.lambda.functions
	some permission in func.permissions
	endswith(permission.principal.value, ".amazonaws.com")
	sourcearn_is_missed(permission)
	res := result.new(
		"Lambda permission lacks source ARN for *.amazonaws.com principal.",
		metadata.obj_by_path(permission, ["sourcearn"]),
	)
}

sourcearn_is_missed(permission) if value.is_empty(permission.sourcearn)

sourcearn_is_missed(permission) if not permission.sourcearn
