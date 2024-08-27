# METADATA
# title: CloudWatch log groups should be encrypted using CMK
# description: |
#   CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
# custom:
#   id: AVD-AWS-0017
#   avd_id: AVD-AWS-0017
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: log-group-customer-key
#   recommended_action: Enable CMK encryption of CloudWatch Log Groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id
#     good_examples: checks/cloud/aws/cloudwatch/log_group_customer_key.tf.go
#     bad_examples: checks/cloud/aws/cloudwatch/log_group_customer_key.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/cloudwatch/log_group_customer_key.cf.go
#     bad_examples: checks/cloud/aws/cloudwatch/log_group_customer_key.cf.go
package builtin.aws.cloudwatch.aws0017

import rego.v1

deny contains res if {
	some group in input.aws.cloudwatch.loggroups
	group.kmskeyid.value == ""
	res := result.new("Log group is not encrypted.", group)
}
