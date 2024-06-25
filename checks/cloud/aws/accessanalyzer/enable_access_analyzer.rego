# METADATA
# title: Enable IAM Access analyzer for IAM policies about all resources in each region.
# description: |
#   AWS IAM Access Analyzer helps you identify the resources in your organization and
#   accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity.
#   This lets you identify unintended access to your resources and data. Access Analyzer
#   identifies resources that are shared with external principals by using logic-based reasoning
#   to analyze the resource-based policies in your AWS environment. IAM Access Analyzer
#   continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service)
#   keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
# custom:
#   id: AVD-AWS-0175
#   avd_id: AVD-AWS-0175
#   provider: aws
#   service: accessanalyzer
#   severity: LOW
#   short_code: enable-access-analyzer
#   recommended_action: Enable IAM Access analyzer across all regions.
#   frameworks:
#     cis-aws-1.4:
#       - "1.20"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: accessanalyzer
#             provider: aws
package builtin.aws.accessanalyzer.aws0175

import rego.v1

deny contains res if {
	not has_active_analyzer
	res := result.new("Access Analyzer is not enabled.", {})
}

has_active_analyzer if {
	some analyzer in input.aws.accessanalyzer.analyzers
	analyzer.active.value
}
