# METADATA
# title: Cloudtrail log validation should be enabled to prevent tampering of log data
# description: |
#   Illicit activity could be removed from the logs. Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
# custom:
#   id: AVD-AWS-0016
#   avd_id: AVD-AWS-0016
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: enable-log-validation
#   recommended_action: Turn on log validation for Cloudtrail
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudtrail
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation
#     good_examples: checks/cloud/aws/cloudtrail/enable_log_validation.tf.go
#     bad_examples: checks/cloud/aws/cloudtrail/enable_log_validation.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/cloudtrail/enable_log_validation.cf.go
#     bad_examples: checks/cloud/aws/cloudtrail/enable_log_validation.cf.go
package builtin.aws.cloudtrail.aws0016

import rego.v1

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	not trail.enablelogfilevalidation.value
	res := result.new("Trail does not have log validation enabled.", trail.enablelogfilevalidation)
}
