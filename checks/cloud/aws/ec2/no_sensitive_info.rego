# METADATA
# title: Ensure all data stored in the launch configuration EBS is securely encrypted
# description: |
#   When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AWS-0122
#   avd_id: AVD-AWS-0122
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-sensitive-info
#   recommended_action: Don't use sensitive data in user data
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data,user_data_base64
#     good_examples: checks/cloud/aws/ec2/no_sensitive_info.tf.go
#     bad_examples: checks/cloud/aws/ec2/no_sensitive_info.tf.go
package builtin.aws.ec2.aws0122

import rego.v1

deny contains res if {
	some conf in input.aws.ec2.launchconfigurations
	scan_result := squealer.scan_string(conf.userdata.value)
	scan_result.transgressionFound
	res := result.new(
		sprintf("Sensitive data found in user data: %s", [scan_result.description]),
		conf.userdata,
	)
}
